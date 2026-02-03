package features

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// OPTIMIZATION: Compile Regex once at startup, not every function call.
var (
	reEval     = regexp.MustCompile(`eval\s*\(`)
	reUnescape = regexp.MustCompile(`unescape\s*\(`)
	reDocWrite = regexp.MustCompile(`document\.write`)
	reLoc      = regexp.MustCompile(`window\.location`)
)

func ExtractFeatures(htmlContent string, targetUrl string, featureOrder []string) ([]float32, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}

	// 1. Pre-calculate values
	// FIX: Handle malformed URLs gracefully to prevent Panic
	parsedUrl, err := url.Parse(targetUrl)
	if err != nil {
		// If URL is garbage, treat it as empty/safe to avoid crash
		parsedUrl = &url.URL{}
	}

	textLen := float32(len(doc.Text()))
	htmlLen := float32(len(htmlContent))

	scripts := doc.Find("script")
	var scriptContent strings.Builder
	scripts.Each(func(i int, s *goquery.Selection) {
		scriptContent.WriteString(s.Text())
	})
	fullScriptStr := scriptContent.String()

	// 2. Map features to a map first
	f := make(map[string]float32)

	// --- Structural ---
	f["html_len"] = htmlLen
	f["text_len"] = textLen
	if htmlLen > 0 {
		f["text_ratio"] = textLen / htmlLen
	} else {
		f["text_ratio"] = 0
	}
	f["has_title"] = boolToFloat(doc.Find("title").Length() > 0)
	f["title_len"] = float32(len(doc.Find("title").Text()))
	f["num_meta_tags"] = float32(doc.Find("meta").Length())

	// --- Scripting ---
	f["num_script_tags"] = float32(scripts.Length())
	f["script_len"] = float32(len(fullScriptStr))
	
	// Use pre-compiled regex
	f["count_eval"] = float32(len(reEval.FindAllString(fullScriptStr, -1)))
	f["count_unescape"] = float32(len(reUnescape.FindAllString(fullScriptStr, -1)))
	f["count_doc_write"] = float32(len(reDocWrite.FindAllString(fullScriptStr, -1)))
	f["count_redirect"] = float32(len(reLoc.FindAllString(fullScriptStr, -1)))

	// --- Elements ---
	f["num_iframes"] = float32(doc.Find("iframe").Length())
	f["num_forms"] = float32(doc.Find("form").Length())
	f["num_inputs"] = float32(doc.Find("input").Length())
	f["num_hidden_tags"] = float32(doc.Find("input[type=hidden]").Length())
	f["num_password_inputs"] = float32(doc.Find("input[type=password]").Length())

	externalLinks := 0
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		if strings.HasPrefix(href, "http") {
			externalLinks++
		}
	})
	f["num_external_links"] = float32(externalLinks)

	// --- Keywords (Case insensitive) ---
	lowerText := strings.ToLower(doc.Text())
	f["kw_malware"] = countKeywords(lowerText, []string{"verify", "account", "suspended", "confirm", "security", "urgent"})
	f["kw_adware"] = countKeywords(lowerText, []string{"winner", "spin", "bonus", "casino", "prize", "jackpot"})
	f["kw_crypto"] = countKeywords(lowerText, []string{"bitcoin", "crypto", "wallet", "mining"})
	f["kw_action"] = countKeywords(lowerText, []string{"download", "play", "install", "stream"})

	// --- URL Features ---
	// Safety Check: parsedUrl is now guaranteed non-nil, even if empty
	f["is_https"] = boolToFloat(parsedUrl.Scheme == "https")
	f["domain_len"] = float32(len(parsedUrl.Hostname()))
	f["path_len"] = float32(len(parsedUrl.Path))
	f["domain_digits"] = countDigits(parsedUrl.Hostname())

	// 3. Flatten to Slice based on strict order
	var inputTensor []float32
	for _, name := range featureOrder {
		if val, ok := f[name]; ok {
			inputTensor = append(inputTensor, val)
		} else {
			inputTensor = append(inputTensor, 0.0)
		}
	}

	return inputTensor, nil
}

// Helpers
func boolToFloat(b bool) float32 {
	if b {
		return 1.0
	}
	return 0.0
}

func countKeywords(text string, kws []string) float32 {
	count := 0
	for _, kw := range kws {
		count += strings.Count(text, kw)
	}
	return float32(count)
}

func countDigits(s string) float32 {
	count := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			count++
		}
	}
	return float32(count)
}