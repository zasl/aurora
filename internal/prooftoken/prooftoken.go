package prooftoken

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"aurora/internal/turnstile"
)

const (
	powPrefixRequirements = "gAAAAAC"
	powPrefixProof        = "gAAAAAB"

	powFallback = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

	maxProofIter = 500_000

	tokenSuffix = "~S"
)

var (
	powCores   = []int{8, 16, 24, 32}
	powScreens = []int{3000, 4000, 5000}

	// config[10] 候选：navigator 原型方法的 toString 表征
	powNavKeys = []string{
		"clearOriginJoinedAdInterestGroups−function clearOriginJoinedAdInterestGroups() { [native code] }",
		"canLoadAdAuctionFencedFrame−function canLoadAdAuctionFencedFrame() { [native code] }",
		"clipboard−[object Clipboard]",
		"getBattery−function getBattery() { [native code] }",
		"getGamepads−function getGamepads() { [native code] }",
		"javaEnabled−function javaEnabled() { [native code] }",
		"sendBeacon−function sendBeacon() { [native code] }",
		"vibrate−function vibrate() { [native code] }",
	}

	// config[12] 候选：window 随机 key
	powWinKeys = []string{
		"requestIdleCallback", "webkitRequestAnimationFrame", "onfocus", "onblur",
	}

	defaultScriptSources = []string{"https://chatgpt.com/backend-api/sentinel/sdk.js"}
)

// generateFingerprint 生成 25 元素浏览器指纹数组。
// attempt/elapsedMs 为 nil 时填充 Math.random()（requirements_token 模式）；
// 非 nil 时填入 PoW nonce 和耗时（proof_token 模式）。
func generateFingerprint(
	userAgent string,
	scriptSources []string,
	deviceID string,
	attempt *int,
	elapsedMs *float64,
) []interface{} {
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0"
	}
	if len(scriptSources) == 0 {
		scriptSources = defaultScriptSources
	}
	//nolint:gosec
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	nowMs := float64(time.Now().UnixMilli())
	perfNow := float64(int64(rng.Float64()*49000)+1000) + rng.Float64() // [1000, 50000)
	timeOrigin := nowMs - perfNow

	scriptSrc := scriptSources[rng.Intn(len(scriptSources))]
	screenW := powScreens[rng.Intn(len(powScreens))]

	var c3, c9 interface{}
	if attempt != nil {
		c3 = *attempt
	} else {
		c3 = rng.Float64()
	}
	if elapsedMs != nil {
		c9 = int(*elapsedMs)
	} else {
		c9 = rng.Float64()
	}

	// _reactListening + 11 位随机小写字母数字
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	reactSuffix := make([]byte, 11)
	for i := range reactSuffix {
		reactSuffix[i] = letters[rng.Intn(len(letters))]
	}

	return []interface{}{
		screenW + screenW/2,                     // [0]  screen.width + screen.height
		_legacyParseTime(),                      // [1]  Date.prototype.toString()
		int64(4294967296),                       // [2]  jsHeapSizeLimit (Chrome 4GB)
		c3,                                      // [3]  Math.random() / PoW nonce
		userAgent,                               // [4]  navigator.userAgent
		scriptSrc,                               // [5]  currentScript.src
		nil,                                     // [6]  documentElement[data-build]
		"zh-CN",                                 // [7]  navigator.language
		"zh-CN,en,en-GB,en-US",                  // [8]  navigator.languages.join(",")
		c9,                                      // [9]  Math.random() / PoW 耗时 ms
		powNavKeys[rng.Intn(len(powNavKeys))],   // [10] 随机 navigator 原型方法
		"_reactListening" + string(reactSuffix), // [11] document 随机 key
		powWinKeys[rng.Intn(len(powWinKeys))],   // [12] window 随机 key
		perfNow,                                 // [13] performance.now()
		deviceID,                                // [14] sid / device_id
		"",                                      // [15] location.search
		powCores[rng.Intn(len(powCores))],       // [16] hardwareConcurrency
		timeOrigin,                              // [17] performance.timeOrigin
		0, 0, 0, 0, 0, 0, 0,                     // [18-24] "X in window" 检查（全部 0）
	}
}

func _legacyParseTime() string {
	loc := time.FixedZone("EST", -5*60*60)
	return time.Now().In(loc).Format("Mon Jan 02 2006 15:04:05") + " GMT-0500 (Eastern Standard Time)"
}

// encodeConfig 将 config 数组编码为 base64 字符串（对齐 SDK 的 N() 函数）。
func encodeConfig(config []interface{}) string {
	raw := marshalCompact(config)
	return base64.StdEncoding.EncodeToString(raw)
}

// ── FNV-1a 哈希（对齐 SDK 哈希函数）─────────────────────────────────────────

func fnv1aHash(text string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(text); i++ {
		h ^= uint32(text[i])
		h = imul(h, 16777619)
	}
	h ^= h >> 16
	h = imul(h, 2246822507)
	h ^= h >> 13
	h = imul(h, 3266489909)
	h ^= h >> 16
	return h
}

func imul(a, b uint32) uint32 {
	return a * b // Go uint32 乘法自动截断，等价于 JS Math.imul
}

func fnv1aHex(text string) string {
	return fmt.Sprintf("%08x", fnv1aHash(text))
}

// ── Requirements Token（无 PoW）─────────────────────────────────────────────

// RequirementsToken 生成 requirements token。
// 对齐 sentinel.py: generate_requirements_token = "gAAAAAC" + encode(config) + "~S"
func RequirementsToken(userAgent string, scriptSources []string, deviceID string) string {
	config := generateFingerprint(userAgent, scriptSources, deviceID, nil, nil)
	return powPrefixRequirements + encodeConfig(config) + tokenSuffix
}

// ── Proof Token（FNV-1a PoW）────────────────────────────────────────────────

// SolveProofToken 计算 Proof of Work token。
// 对齐 sentinel.py: solve_proof_of_work，哈希用 FNV-1a，返回 "gAAAAAB" + encoded + "~S"。
func SolveProofToken(seed, difficulty, userAgent string, scriptSources []string, deviceID string) string {
	if seed == "" || difficulty == "" {
		return ""
	}

	startTime := float64(time.Now().UnixMilli())
	attempt := 0
	elapsed := 0.0
	config := generateFingerprint(userAgent, scriptSources, deviceID, &attempt, &elapsed)

	timeOrigin := config[17].(float64)
	diffLen := len(difficulty)

	for i := 0; i < maxProofIter; i++ {
		elapsedNow := float64(time.Now().UnixMilli()) - startTime
		config[3] = i
		config[9] = int(elapsedNow)
		config[13] = timeOrigin - startTime + elapsedNow // performance.now() 与 timeOrigin 自洽

		encoded := encodeConfig(config)
		hashResult := fnv1aHex(seed + encoded)

		if hashResult[:diffLen] <= difficulty {
			return powPrefixProof + encoded + tokenSuffix
		}
	}

	return powPrefixProof + powFallback + encodeConfig([]interface{}{"e"})
}

// ── helpers ─────────────────────────────────────────────────────────────────

func marshalCompact(v interface{}) []byte {
	b, _ := json.Marshal(v)
	buf := new(bytes.Buffer)
	_ = json.Compact(buf, b)
	return buf.Bytes()
}

// Solve delegates to the canonical turnstile VM implementation.
func Solve(dx string, p string) string {
	return turnstile.Solve(dx, p)
}
