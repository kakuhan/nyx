// APK builder — pure Go.
// Usage: go run . <build-dir> <output.apk>
package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: build-apk <build-dir> <output.apk>\n")
		os.Exit(1)
	}
	buildDir := os.Args[1]
	outPath := os.Args[2]

	apkBuf := new(bytes.Buffer)
	zw := zip.NewWriter(apkBuf)

	// 1. AndroidManifest.xml (binary AXML) — MUST be first entry
	writeManifest(zw)

	// 2. resources.arsc — REQUIRED for PackageManager
	writeArsc(zw)

	// 3. classes.dex
	writeFileFromDisk(zw, filepath.Join(buildDir, "dex-output", "classes.dex"), "classes.dex")

	// 4. assets/
	assetsDir := filepath.Join(buildDir, "assets")
	filepath.Walk(assetsDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(buildDir, path)
		writeFileFromDisk(zw, path, rel)
		return nil
	})

	// 5. lib/ — store uncompressed (Android requirement)
	libDir := filepath.Join(buildDir, "lib")
	filepath.Walk(libDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(buildDir, path)
		data, _ := os.ReadFile(path)
		header := &zip.FileHeader{
			Name:   rel,
			Method: zip.Store, // Native libs MUST be stored uncompressed
		}
		header.SetMode(0444)
		w, _ := zw.CreateHeader(header)
		w.Write(data)
		return nil
	})

	zw.Close()

	// Write to file
	err := os.WriteFile(outPath, apkBuf.Bytes(), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outPath, err)
		os.Exit(1)
	}

	info, _ := os.Stat(outPath)
	fmt.Printf("APK created: %s (%d bytes)\n", outPath, info.Size())
}

func writeManifest(zw *zip.Writer) {
	data := buildAXML()
	header := &zip.FileHeader{
		Name:   "AndroidManifest.xml",
		Method: zip.Deflate,
	}
	w, _ := zw.CreateHeader(header)
	w.Write(data)
}

func writeArsc(zw *zip.Writer) {
	data := buildArsc()
	header := &zip.FileHeader{
		Name:   "resources.arsc",
		Method: zip.Deflate,
	}
	w, _ := zw.CreateHeader(header)
	w.Write(data)
}

func writeFileFromDisk(zw *zip.Writer, srcPath, zipName string) {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: skipping %s: %v\n", srcPath, err)
		return
	}
	header := &zip.FileHeader{
		Name:   zipName,
		Method: zip.Deflate,
	}
	w, _ := zw.CreateHeader(header)
	w.Write(data)
}

// --- AXML Builder ---

type axmlWriter struct {
	buf       bytes.Buffer
	strings   map[string]uint32
	stringBuf bytes.Buffer
}

func newAXML() *axmlWriter {
	w := &axmlWriter{strings: make(map[string]uint32)}
	w.str("") // string 0
	return w
}

func (w *axmlWriter) str(s string) uint32 {
	if id, ok := w.strings[s]; ok {
		return id
	}
	id := uint32(len(w.strings))
	w.strings[s] = id
	// UTF-8 encoding: u8 charCount + u8 byteCount + raw UTF-8 bytes + NULL terminator
	// charCount = number of UTF-16 code units needed (len([]rune(s)))
	// byteCount = strlen of UTF-8 bytes
	charCount := uint8(len([]rune(s)))
	utf8Bytes := []byte(s)
	byteCount := uint8(len(utf8Bytes))
	w.stringBuf.WriteByte(charCount)
	w.stringBuf.WriteByte(byteCount)
	w.stringBuf.Write(utf8Bytes)
	w.stringBuf.WriteByte(0x00) // NULL terminator
	return id
}


func (w *axmlWriter) u16(v uint16) { binary.Write(&w.buf, binary.LittleEndian, v) }
func (w *axmlWriter) u32(v uint32) { binary.Write(&w.buf, binary.LittleEndian, v) }

type axAttr struct {
	ns, name, rawValue uint32
	dataType            uint8 // 0x03=string, 0x12=bool, 0x10=int
	data                uint32 // typed value
}

const (
	attrTypeString = uint8(0x03)
	attrTypeBool   = uint8(0x12)
	attrTypeInt    = uint8(0x10)
)

func strAttr(ns, name, val uint32) axAttr {
	return axAttr{ns, name, val, attrTypeString, val}
}
const noStringRef = uint32(0xFFFFFFFF)

func boolAttr(ns, name uint32, val bool) axAttr {
	d := uint32(0)
	if val {
		d = 0xFFFFFFFF
	}
	return axAttr{ns, name, noStringRef, attrTypeBool, d}
}
func intAttr(ns, name, val uint32) axAttr {
	return axAttr{ns, name, noStringRef, attrTypeInt, val}
}

func buildAXML() []byte {
	w := newAXML()
	w.str("") // string 0 always empty
	nsURI := w.str("http://schemas.android.com/apk/res/android")
	nsPrefix := w.str("android")

	// === Build entire XML tree into temp buffer first ===
	// This collects all strings via w.str() calls
	var treeBuf bytes.Buffer

	// Namespace
	writeLE(&treeBuf, uint16(0x0100)) // START_NS
	writeLE(&treeBuf, uint16(0x0010))
	writeLE(&treeBuf, uint32(0x00000018))
	writeLE(&treeBuf, uint32(0xFFFFFFFF))
	writeLE(&treeBuf, uint32(0xFFFFFFFF))
	writeLE(&treeBuf, nsPrefix)
	writeLE(&treeBuf, nsURI)

	// manifest tag
	writeStartTag(&treeBuf, w.str("manifest"), []axAttr{
		strAttr(0xFFFFFFFF, w.str("package"), w.str("com.nyx.proxy")),
		intAttr(nsURI, w.str("versionCode"), 1),
		strAttr(nsURI, w.str("versionName"), w.str("1.0")),
		intAttr(nsURI, w.str("compileSdkVersion"), 35),
	})
	// uses-sdk
	writeStartTag(&treeBuf, w.str("uses-sdk"), []axAttr{
		intAttr(nsURI, w.str("minSdkVersion"), 21),
		intAttr(nsURI, w.str("targetSdkVersion"), 35),
	})
	writeEndTag(&treeBuf, w.str("uses-sdk"))
	// uses-permission (INTERNET)
	writeStartTag(&treeBuf, w.str("uses-permission"), []axAttr{
		strAttr(nsURI, w.str("name"), w.str("android.permission.INTERNET")),
	})
	writeEndTag(&treeBuf, w.str("uses-permission"))
	// uses-permission (FOREGROUND_SERVICE)
	writeStartTag(&treeBuf, w.str("uses-permission"), []axAttr{
		strAttr(nsURI, w.str("name"), w.str("android.permission.FOREGROUND_SERVICE")),
	})
	writeEndTag(&treeBuf, w.str("uses-permission"))
	// uses-permission (FOREGROUND_SERVICE_SPECIAL_USE) — Android 14+
	writeStartTag(&treeBuf, w.str("uses-permission"), []axAttr{
		strAttr(nsURI, w.str("name"), w.str("android.permission.FOREGROUND_SERVICE_SPECIAL_USE")),
	})
	writeEndTag(&treeBuf, w.str("uses-permission"))
	// application
	writeStartTag(&treeBuf, w.str("application"), []axAttr{
		strAttr(nsURI, w.str("label"), w.str("Nyx")),
		boolAttr(nsURI, w.str("extractNativeLibs"), true),
	})
	// activity
	writeStartTag(&treeBuf, w.str("activity"), []axAttr{
		strAttr(nsURI, w.str("name"), w.str("com.nyx.proxy.MainActivity")),
		boolAttr(nsURI, w.str("exported"), true),
	})
	writeStartTag(&treeBuf, w.str("intent-filter"), nil)
	writeStartTag(&treeBuf, w.str("action"), []axAttr{
		strAttr(nsURI, w.str("name"), w.str("android.intent.action.MAIN")),
	})
	writeEndTag(&treeBuf, w.str("action"))
	writeStartTag(&treeBuf, w.str("category"), []axAttr{
		strAttr(nsURI, w.str("name"), w.str("android.intent.category.LAUNCHER")),
	})
	writeEndTag(&treeBuf, w.str("category"))
	writeEndTag(&treeBuf, w.str("intent-filter"))
	writeEndTag(&treeBuf, w.str("activity"))
	// service (foreground)
	writeStartTag(&treeBuf, w.str("service"), []axAttr{
		strAttr(nsURI, w.str("name"), w.str("com.nyx.proxy.NyxService")),
		boolAttr(nsURI, w.str("exported"), false),
		strAttr(nsURI, w.str("foregroundServiceType"), w.str("specialUse")),
	})
	// Android 14+ REQUIRED: explain why specialUse foreground service
	writeStartTag(&treeBuf, w.str("property"), []axAttr{
		strAttr(nsURI, w.str("name"), w.str("android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE")),
		strAttr(nsURI, w.str("value"), w.str("VPN/tunnel proxy requires persistent background service")),
	})
	writeEndTag(&treeBuf, w.str("property"))
	writeEndTag(&treeBuf, w.str("service"))
	writeEndTag(&treeBuf, w.str("application"))
	writeEndTag(&treeBuf, w.str("manifest"))

	// End namespace
	writeLE(&treeBuf, uint16(0x0101))
	writeLE(&treeBuf, uint16(0x0010))
	writeLE(&treeBuf, uint32(0x00000018))
	writeLE(&treeBuf, uint32(0xFFFFFFFF))
	writeLE(&treeBuf, uint32(0xFFFFFFFF))
	writeLE(&treeBuf, nsPrefix)
	writeLE(&treeBuf, nsURI)

	treeData := treeBuf.Bytes()

	// === NOW build the final AXML output ===
	var out bytes.Buffer

	// AXML header
	writeLE(&out, uint32(0x00080003)) // magic
	writeLE(&out, uint32(0))          // total size placeholder

	// String pool
	spStart := out.Len()
	writeLE(&out, uint16(0x0001)) // RES_STRING_POOL_TYPE
	writeLE(&out, uint16(0x001C)) // header size
	spSizePos := out.Len()
	writeLE(&out, uint32(0)) // chunk size placeholder
	writeLE(&out, uint32(len(w.strings))) // count
	writeLE(&out, uint32(0)) // style count
	writeLE(&out, uint32(0x00000100)) // flags: UTF-8 encoding

	// Sort strings by ID
	ordered := make([]string, len(w.strings))
	for s, id := range w.strings {
		ordered[id] = s
	}

	// Strings start offset = header(28) + count*4 + styleCount*4
	stringsStart := uint32(28 + len(w.strings)*4 + 0)
	writeLE(&out, stringsStart)
	writeLE(&out, stringsStart) // styles_start

	// String offsets — each string is: u8 charCount + u8 byteCount + UTF-8 bytes + NULL
	// Total bytes = 2 + len([]byte(s)) + 1
	off := uint32(0)
	for _, s := range ordered {
		writeLE(&out, off)
		off += uint32(2 + len([]byte(s)) + 1)
	}

	// String data
	sd := w.stringBuf.Bytes()
	spDataLen := uint32(len(sd))
	pad := (4 - spDataLen%4) % 4
	spSize := uint32(out.Len()-spStart) + spDataLen + pad

	raw := out.Bytes()
	binary.LittleEndian.PutUint32(raw[spSizePos:spSizePos+4], spSize)

	out.Write(sd)
	for i := uint32(0); i < pad; i++ {
		out.WriteByte(0)
	}

	// Resource map (0x0180): maps string pool indices to Android resource IDs.
	// PackageManager requires this to resolve android: attributes.
	// Each string gets one uint32 resource ID entry.
	// Attribute names in the android namespace get their well-known resource ID;
	// all other strings (values, element names, namespace URIs) get 0.
	attrRID := map[string]uint32{
		"versionCode":                0x0101021B,
		"versionName":                0x0101021C,
		"compileSdkVersion":          0x01010572,
		"compileSdkVersionCodename":  0x01010573,
		"minSdkVersion":              0x0101020C,
		"targetSdkVersion":           0x01010270,
		"name":                       0x01010003,
		"label":                      0x01010001,
		"exported":                   0x01010010,
		"foregroundServiceType":      0x01010599,
	}
	rmNumEntries := uint32(len(ordered))
	rmSize := uint32(8 + rmNumEntries*4)
	writeLE(&out, uint16(0x0180))
	writeLE(&out, uint16(0x0008))
	writeLE(&out, rmSize)
	for _, s := range ordered {
		writeLE(&out, attrRID[s]) // 0 if not found (correct for non-attribute strings)
	}

	// XML tree
	out.Write(treeData)

	// Total size
	raw = out.Bytes()
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(raw)))
	return raw
}

func writeLE(w io.Writer, v interface{}) {
	binary.Write(w, binary.LittleEndian, v)
}

func writeStartTag(w io.Writer, name uint32, attrs []axAttr) {
	// ResXMLTree_node (24 bytes) + attrExt (12 bytes) + attrs (n*20)
	chunkSize := 36 + len(attrs)*20
	binary.Write(w, binary.LittleEndian, uint16(0x0102))  // RES_XML_START_ELEMENT_TYPE
	binary.Write(w, binary.LittleEndian, uint16(0x0010))   // headerSize = 16
	binary.Write(w, binary.LittleEndian, uint32(chunkSize))
	binary.Write(w, binary.LittleEndian, uint32(0xFFFFFFFF)) // lineNumber
	binary.Write(w, binary.LittleEndian, uint32(0xFFFFFFFF)) // comment index
	binary.Write(w, binary.LittleEndian, uint32(0xFFFFFFFF)) // namespace index
	binary.Write(w, binary.LittleEndian, name)                // element name
	binary.Write(w, binary.LittleEndian, uint16(0x0014))      // attributeStart (=20, offset of first attr from attrExt start)
	binary.Write(w, binary.LittleEndian, uint16(0x0014))      // attributeSize (=20, each attr is ResXMLTree_attribute = 20 bytes)
	binary.Write(w, binary.LittleEndian, uint16(len(attrs)))  // attributeCount
	binary.Write(w, binary.LittleEndian, uint16(0x0000))      // idIndex
	binary.Write(w, binary.LittleEndian, uint16(0x0000))      // classIndex
	binary.Write(w, binary.LittleEndian, uint16(0x0000))      // styleIndex
	for _, a := range attrs {
		binary.Write(w, binary.LittleEndian, a.ns)
		binary.Write(w, binary.LittleEndian, a.name)
		binary.Write(w, binary.LittleEndian, a.rawValue)
		binary.Write(w, binary.LittleEndian, uint16(0x0008)) // size
		w.(io.ByteWriter).WriteByte(0x00)                     // reserved
		w.(io.ByteWriter).WriteByte(a.dataType)               // type
		binary.Write(w, binary.LittleEndian, a.data)          // data
	}
}

func writeEndTag(w io.Writer, name uint32) {
	binary.Write(w, binary.LittleEndian, uint16(0x0103))
	binary.Write(w, binary.LittleEndian, uint16(0x0010))
	binary.Write(w, binary.LittleEndian, uint32(0x00000018))
	binary.Write(w, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(w, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(w, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(w, binary.LittleEndian, name)
}

func (w *axmlWriter) u8(v uint8) { w.buf.WriteByte(v) }

// --- Minimal ARSC ---

func buildArsc() []byte {
	var buf bytes.Buffer

	// === RES_TABLE header ===
	binary.Write(&buf, binary.LittleEndian, uint16(0x0002)) // RES_TABLE_TYPE
	binary.Write(&buf, binary.LittleEndian, uint16(0x000C)) // header size
	sizePos := buf.Len()
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // chunk size placeholder
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // 1 package

	// === Global string pool (empty) ===
	binary.Write(&buf, binary.LittleEndian, uint16(0x0001)) // RES_STRING_POOL_TYPE
	binary.Write(&buf, binary.LittleEndian, uint16(0x001C)) // header size
	binary.Write(&buf, binary.LittleEndian, uint32(0x0000001C)) // chunk size
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // string count
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // style count
	binary.Write(&buf, binary.LittleEndian, uint32(0x00000000)) // flags
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // strings start
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // styles start

	// === Package chunk (type 0x0200) ===
	// Package name as UTF-16LE with 2-byte length prefix:
	// [2 bytes: UTF-16 char count][UTF-16LE chars][2 bytes: null]
	nameStr := "com.nyx.proxy"
	pkgName := make([]byte, 0, 2+len(nameStr)*2+2)
	pkgName = append(pkgName, byte(len([]rune(nameStr))), 0x00) // char count (uint16 LE)
	for _, r := range nameStr {
		pkgName = append(pkgName, byte(r), 0x00)
	}
	pkgName = append(pkgName, 0x00, 0x00) // null terminator
	// Pad name to 4-byte alignment
	for len(pkgName)%4 != 0 {
		pkgName = append(pkgName, 0)
	}

	typeStrings := buildArscStringPool([]string{}) // empty type string pool
	keyStrings := buildArscStringPool([]string{})  // empty key string pool

	// Package chunk header
	pkgStart := buf.Len()                              // save position for relative offsets
	pkgHeaderSize := 288                                // 0x0120
	pkgChunkSize := pkgHeaderSize + len(typeStrings) + len(keyStrings)

	binary.Write(&buf, binary.LittleEndian, uint16(0x0200)) // RES_TABLE_PACKAGE_TYPE
	binary.Write(&buf, binary.LittleEndian, uint16(pkgHeaderSize))
	binary.Write(&buf, binary.LittleEndian, uint32(pkgChunkSize))
	binary.Write(&buf, binary.LittleEndian, uint32(0x7F))   // package id
	buf.Write(pkgName)
	// typeStrings offset (relative to chunk start)
	binary.Write(&buf, binary.LittleEndian, uint32(pkgHeaderSize))
	// lastPublicType
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// keyStrings offset (relative to chunk start)
	binary.Write(&buf, binary.LittleEndian, uint32(pkgHeaderSize+len(typeStrings)))
	// lastPublicKey
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// typeIdOffset
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// Pad to pkgHeaderSize bytes (from package chunk start)
	pkgTarget := pkgStart + pkgHeaderSize
	for buf.Len() < pkgTarget {
		buf.WriteByte(0)
	}
	buf.Write(typeStrings)
	buf.Write(keyStrings)

	// Write total size
	raw := buf.Bytes()
	binary.LittleEndian.PutUint32(raw[sizePos:sizePos+4], uint32(len(raw)))
	return raw
}

func buildArscStringPool(strings []string) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint16(0x0001)) // RES_STRING_POOL_TYPE
	binary.Write(&buf, binary.LittleEndian, uint16(0x001C)) // header size
	sizePos := buf.Len()
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(len(strings)))
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // style count
	binary.Write(&buf, binary.LittleEndian, uint32(0x00000100)) // flags: UTF-8
	stringsStart := uint32(28 + len(strings)*4)
	binary.Write(&buf, binary.LittleEndian, uint32(stringsStart))
	binary.Write(&buf, binary.LittleEndian, uint32(stringsStart)) // styles start
	off := uint32(0)
	for _, s := range strings {
		binary.Write(&buf, binary.LittleEndian, off)
		off += uint32(2 + len([]byte(s)) + 1)
	}
	for _, s := range strings {
		charCount := uint8(len([]rune(s)))
		utf8Bytes := []byte(s)
		byteCount := uint8(len(utf8Bytes))
		buf.WriteByte(charCount)
		buf.WriteByte(byteCount)
		buf.Write(utf8Bytes)
		buf.WriteByte(0x00) // NULL terminator
	}
	raw := buf.Bytes()
	binary.LittleEndian.PutUint32(raw[sizePos:sizePos+4], uint32(len(raw)))
	return raw
}
