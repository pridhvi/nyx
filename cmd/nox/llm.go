package nox

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kanini/nox/internal/config"
	"github.com/kanini/nox/internal/db"
	llmintel "github.com/kanini/nox/internal/llm"
)

func runLLM(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("supported llm commands: chat <session-id>, analyse <session-id>")
	}
	switch args[0] {
	case "chat":
		return runLLMChat(args[1:])
	case "analyse":
		return runLLMAnalyse(args[1:])
	default:
		return fmt.Errorf("supported llm commands: chat <session-id>, analyse <session-id>")
	}
}

func runLLMChat(args []string) error {
	fs := flag.NewFlagSet("llm chat", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	message := fs.String("message", "", "single chat message")
	sessionID, flagArgs := splitLeadingSessionID(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if sessionID == "" && fs.NArg() > 0 {
		sessionID = fs.Arg(0)
	}
	if sessionID == "" {
		return fmt.Errorf("llm chat requires a session id")
	}
	prompt := strings.TrimSpace(*message)
	if prompt == "" {
		fmt.Print("message: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			prompt = scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	}
	if prompt == "" {
		return fmt.Errorf("message is required")
	}
	return runLLMPrompt(*cfgPath, sessionID, prompt)
}

func runLLMAnalyse(args []string) error {
	fs := flag.NewFlagSet("llm analyse", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	sessionID, flagArgs := splitLeadingSessionID(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if sessionID == "" && fs.NArg() > 0 {
		sessionID = fs.Arg(0)
	}
	if sessionID == "" {
		return fmt.Errorf("llm analyse requires a session id")
	}
	return runLLMPrompt(*cfgPath, sessionID, "Review the completed scan. Summarize the highest-confidence risks, relevant CVEs, deterministic attack vectors, and safe follow-up checks.")
}

func runLLMPrompt(configPath, sessionID, prompt string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	store, err := db.OpenSession(context.Background(), firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir()), sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	session, err := store.GetSession(context.Background())
	if err != nil {
		return err
	}
	if session.LLMBaseURL == "" {
		session.LLMBaseURL = cfg.LLM.BaseURL
	}
	if session.LLMModel == "" {
		session.LLMModel = cfg.LLM.Model
	}
	llmConfig := llmintel.ConfigFromSession(session)
	if !llmConfig.Configured() {
		return llmintel.ErrNotConfigured
	}
	analysis, err := llmintel.NewAnalyst(store, nil, llmConfig).AnalyzeSession(context.Background(), session.ID, prompt)
	if err != nil {
		if errors.Is(err, llmintel.ErrNotConfigured) {
			return fmt.Errorf("LLM is not configured; set NOX_LLM_BASE_URL or configure llm.base_url")
		}
		return err
	}
	for i := len(analysis.Messages) - 1; i >= 0; i-- {
		if analysis.Messages[i].Role == "assistant" && strings.TrimSpace(analysis.Messages[i].Content) != "" {
			fmt.Println(analysis.Messages[i].Content)
			return nil
		}
	}
	fmt.Printf("stored LLM analysis %s\n", analysis.ID)
	return nil
}
