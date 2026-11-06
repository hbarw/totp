package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

func generateTOTP(secret string, timestamp time.Time) (string, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if padding := len(secret) % 8; padding > 0 {
		secret += strings.Repeat("=", 8-padding)
	}

	keyBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("无效的 Base32 密钥: %w", err)
	}

	epoch := timestamp.Unix()
	counter := epoch / 30

	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))

	mac := hmac.New(sha1.New, keyBytes)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	codeInt := int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1]&0xff)<<16 |
		int(hash[offset+2]&0xff)<<8 |
		int(hash[offset+3]&0xff)

	code := codeInt % 1000000
	return fmt.Sprintf("%06d", code), nil
}

func main() {
	var secret string

	secret = os.Getenv("TOTP_SECRET")

	if secret == "" {
		fmt.Print("请输入 TOTP 密钥: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取输入失败: %v\n", err)
			os.Exit(1)
		}
		secret = strings.TrimSpace(string(bytePassword))
	}

	if secret == "" {
		fmt.Fprintln(os.Stderr, "密钥不能为空")
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n已退出！")
		os.Exit(0)
	}()

	fmt.Println("正在生成 TOTP 验证码（按 Ctrl+C 退出）...")

	for {
		now := time.Now()
		code, err := generateTOTP(secret, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n%v\n", err)
			os.Exit(1)
		}

		timeLeft := int(30 - (now.Unix() % 30))
		bar := strings.Repeat("█", timeLeft) + strings.Repeat("░", 30-timeLeft)

		fmt.Printf("\r验证码: %s  剩余: %2ds  [%s]", code, timeLeft, bar)

		time.Sleep(1 * time.Second)
	}
}
