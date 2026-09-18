//go:build ignore

// Command mkicon draws the AetherVPN application icon and writes both a PNG
// and a Windows .ico (PNG-compressed entry, supported since Vista).
//
// Run with:  go run tools/mkicon.go
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

const size = 256

func main() {
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	// Rounded-square plate with a blue -> cyan diagonal gradient.
	r := 54.0
	from := [3]float64{43, 110, 245} // #2b6ef5
	to := [3]float64{13, 139, 216}   // #0d8bd8
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if !roundedRect(float64(x), float64(y), 8, 8, size-16, size-16, r) {
				continue
			}
			t := (float64(x) + float64(y)) / float64(2*size)
			img.Set(x, y, color.RGBA{
				R: uint8(from[0] + (to[0]-from[0])*t),
				G: uint8(from[1] + (to[1]-from[1])*t),
				B: uint8(from[2] + (to[2]-from[2])*t),
				A: 255,
			})
		}
	}

	white := color.RGBA{255, 255, 255, 255}
	// A bold "A" glyph: two legs and a crossbar.
	stroke(img, 96, 196, 128, 76, 22, white) // left leg
	stroke(img, 128, 76, 160, 196, 22, white) // right leg
	stroke(img, 108, 156, 148, 156, 20, white) // crossbar

	// Three nodes joined by links, evoking a network mesh.
	blue := color.RGBA{43, 110, 245, 255}
	nodes := [][2]int{{104, 104}, {152, 104}, {128, 148}}
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			stroke(img, nodes[i][0], nodes[i][1], nodes[j][0], nodes[j][1], 6, white)
		}
	}
	for _, n := range nodes {
		disc(img, n[0], n[1], 13, blue)
	}

	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		panic(err)
	}

	outDir := "assets"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "app.png"), pngBuf.Bytes(), 0o644); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "app.ico"), ico(pngBuf.Bytes(), size), 0o644); err != nil {
		panic(err)
	}
	println("wrote assets/app.png and assets/app.ico")
}

// ico wraps PNG bytes in a single-image Windows icon container.
func ico(pngData []byte, px int) []byte {
	var b bytes.Buffer
	dim := byte(px)
	if px >= 256 {
		dim = 0 // 256 is encoded as 0
	}
	binary.Write(&b, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&b, binary.LittleEndian, uint16(1)) // type: icon
	binary.Write(&b, binary.LittleEndian, uint16(1)) // image count
	b.WriteByte(dim)                                 // width
	b.WriteByte(dim)                                 // height
	b.WriteByte(0)                                   // palette colours
	b.WriteByte(0)                                   // reserved
	binary.Write(&b, binary.LittleEndian, uint16(1)) // colour planes
	binary.Write(&b, binary.LittleEndian, uint16(32))
	binary.Write(&b, binary.LittleEndian, uint32(len(pngData)))
	binary.Write(&b, binary.LittleEndian, uint32(6+16)) // offset
	b.Write(pngData)
	return b.Bytes()
}

func roundedRect(x, y, rx, ry, w, h, r float64) bool {
	if x < rx || y < ry || x > rx+w || y > ry+h {
		return false
	}
	// Inside the straight parts the point is always covered.
	if (x >= rx+r && x <= rx+w-r) || (y >= ry+r && y <= ry+h-r) {
		return true
	}
	cx, cy := rx+r, ry+r
	if x > rx+w-r {
		cx = rx + w - r
	}
	if y > ry+h-r {
		cy = ry + h - r
	}
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= r*r
}

// stroke draws a thick line by testing the distance to the segment.
func stroke(img *image.RGBA, x0, y0, x1, y1 int, width float64, c color.RGBA) {
	half := width / 2
	minX, maxX := x0, x1
	if minX > maxX {
		minX, maxX = maxX, minX
	}
	minY, maxY := y0, y1
	if minY > maxY {
		minY, maxY = maxY, minY
	}
	for y := minY - int(half) - 1; y <= maxY+int(half)+1; y++ {
		for x := minX - int(half) - 1; x <= maxX+int(half)+1; x++ {
			if distToSeg(float64(x), float64(y), float64(x0), float64(y0), float64(x1), float64(y1)) <= half {
				img.Set(x, y, c)
			}
		}
	}
}

func disc(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx, dy := float64(x-cx), float64(y-cy)
			if dx*dx+dy*dy <= float64(r*r) {
				img.Set(x, y, c)
			}
		}
	}
}

func distToSeg(px, py, x0, y0, x1, y1 float64) float64 {
	vx, vy := x1-x0, y1-y0
	wx, wy := px-x0, py-y0
	l2 := vx*vx + vy*vy
	var t float64
	if l2 > 0 {
		t = (wx*vx + wy*vy) / l2
		if t < 0 {
			t = 0
		} else if t > 1 {
			t = 1
		}
	}
	dx, dy := wx-vx*t, wy-vy*t
	return math.Sqrt(dx*dx + dy*dy)
}
