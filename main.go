package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"unicode"
)

// Estructuras para los tokens y análisis
type Token struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
}

type AnalysisResult struct {
	Tokens         []Token                `json:"tokens"`
	SyntaxErrors   []string               `json:"syntaxErrors"`
	SemanticErrors []string               `json:"semanticErrors"`
	AST            map[string]interface{} `json:"ast"`
}

type AnalyzeRequest struct {
	Code string `json:"code"`
}

// Analizador Léxico simplificado
type Lexer struct {
	input    string
	position int
	line     int
	column   int
}

func NewLexer(input string) *Lexer {
	return &Lexer{
		input:  input,
		line:   1,
		column: 1,
	}
}

func (l *Lexer) hasMore() bool {
	return l.position < len(l.input)
}

func (l *Lexer) current() rune {
	if !l.hasMore() {
		return 0
	}
	return rune(l.input[l.position])
}

func (l *Lexer) next() rune {
	if !l.hasMore() {
		return 0
	}
	ch := rune(l.input[l.position])
	l.position++
	if ch == '\n' {
		l.line++
		l.column = 1
	} else {
		l.column++
	}
	return ch
}

func (l *Lexer) skipWhitespace() {
	for l.hasMore() && unicode.IsSpace(l.current()) {
		l.next()
	}
}

func (l *Lexer) readNumber() string {
	start := l.position
	for l.hasMore() && (unicode.IsDigit(l.current()) || l.current() == '.') {
		l.next()
	}
	if start == l.position {
		return ""
	}
	return l.input[start:l.position]
}

func (l *Lexer) readIdentifier() string {
	start := l.position
	for l.hasMore() {
		ch := l.current()
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_' || ch == '$' {
			l.next()
		} else {
			break
		}
	}
	if start == l.position {
		return ""
	}
	return l.input[start:l.position]
}

func (l *Lexer) readString(quote rune) string {
	start := l.position
	l.next() // skip opening quote
	
	for l.hasMore() {
		ch := l.current()
		if ch == quote {
			l.next() // consume closing quote
			break
		}
		if ch == '\\' && l.position+1 < len(l.input) {
			l.next() // skip escape
		}
		l.next()
	}
	return l.input[start:l.position]
}

func (l *Lexer) Tokenize() []Token {
	var tokens []Token
	keywords := map[string]bool{
		"const": true, "let": true, "var": true, "function": true,
		"if": true, "else": true, "for": true, "while": true,
		"return": true, "true": true, "false": true, "null": true,
		"undefined": true, "console": true, "require": true,
		"module": true, "exports": true, "class": true,
	}

	maxTokens := 10000 // Límite de seguridad
	tokenCount := 0

	for l.hasMore() && tokenCount < maxTokens {
		tokenCount++
		l.skipWhitespace()
		
		if !l.hasMore() {
			break
		}

		line, column := l.line, l.column
		ch := l.current()

		switch {
		case unicode.IsDigit(ch):
			value := l.readNumber()
			if value != "" {
				tokens = append(tokens, Token{
					Type: "NUMBER", Value: value, Line: line, Column: column,
				})
			}

		case unicode.IsLetter(ch) || ch == '_' || ch == '$':
			value := l.readIdentifier()
			if value != "" {
				tokenType := "IDENTIFIER"
				if keywords[value] {
					tokenType = "KEYWORD"
				}
				tokens = append(tokens, Token{
					Type: tokenType, Value: value, Line: line, Column: column,
				})
			}

		case ch == '"' || ch == '\'' || ch == '`':
			value := l.readString(ch)
			tokenType := "STRING"
			if ch == '`' {
				tokenType = "TEMPLATE_LITERAL"
			}
			tokens = append(tokens, Token{
				Type: tokenType, Value: value, Line: line, Column: column,
			})

		case ch == '+':
			l.next()
			if l.hasMore() && l.current() == '+' {
				l.next()
				tokens = append(tokens, Token{Type: "INCREMENT", Value: "++", Line: line, Column: column})
			} else if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "PLUS_ASSIGN", Value: "+=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "PLUS", Value: "+", Line: line, Column: column})
			}

		case ch == '-':
			l.next()
			if l.hasMore() && l.current() == '-' {
				l.next()
				tokens = append(tokens, Token{Type: "DECREMENT", Value: "--", Line: line, Column: column})
			} else if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "MINUS_ASSIGN", Value: "-=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "MINUS", Value: "-", Line: line, Column: column})
			}

		case ch == '*':
			l.next()
			if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "MULTIPLY_ASSIGN", Value: "*=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "MULTIPLY", Value: "*", Line: line, Column: column})
			}

		case ch == '/':
			l.next()
			if l.hasMore() && l.current() == '/' {
				// Comentario de línea
				for l.hasMore() && l.current() != '\n' {
					l.next()
				}
				tokens = append(tokens, Token{Type: "COMMENT", Value: "//", Line: line, Column: column})
			} else if l.hasMore() && l.current() == '*' {
				// Comentario de bloque
				l.next() // consume *
				for l.hasMore() {
					if l.current() == '*' && l.position+1 < len(l.input) && rune(l.input[l.position+1]) == '/' {
						l.next() // consume *
						l.next() // consume /
						break
					}
					l.next()
				}
				tokens = append(tokens, Token{Type: "COMMENT", Value: "/* */", Line: line, Column: column})
			} else if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "DIVIDE_ASSIGN", Value: "/=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "DIVIDE", Value: "/", Line: line, Column: column})
			}

		case ch == '=':
			l.next()
			if l.hasMore() && l.current() == '=' {
				l.next()
				if l.hasMore() && l.current() == '=' {
					l.next()
					tokens = append(tokens, Token{Type: "STRICT_EQUAL", Value: "===", Line: line, Column: column})
				} else {
					tokens = append(tokens, Token{Type: "EQUAL", Value: "==", Line: line, Column: column})
				}
			} else if l.hasMore() && l.current() == '>' {
				l.next()
				tokens = append(tokens, Token{Type: "ARROW", Value: "=>", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "ASSIGN", Value: "=", Line: line, Column: column})
			}

		case ch == '!':
			l.next()
			if l.hasMore() && l.current() == '=' {
				l.next()
				if l.hasMore() && l.current() == '=' {
					l.next()
					tokens = append(tokens, Token{Type: "STRICT_NOT_EQUAL", Value: "!==", Line: line, Column: column})
				} else {
					tokens = append(tokens, Token{Type: "NOT_EQUAL", Value: "!=", Line: line, Column: column})
				}
			} else {
				tokens = append(tokens, Token{Type: "NOT", Value: "!", Line: line, Column: column})
			}

		case ch == '<':
			l.next()
			if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "LESS_EQUAL", Value: "<=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "LESS", Value: "<", Line: line, Column: column})
			}

		case ch == '>':
			l.next()
			if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "GREATER_EQUAL", Value: ">=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "GREATER", Value: ">", Line: line, Column: column})
			}

		case ch == '&':
			l.next()
			if l.hasMore() && l.current() == '&' {
				l.next()
				tokens = append(tokens, Token{Type: "LOGICAL_AND", Value: "&&", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "BITWISE_AND", Value: "&", Line: line, Column: column})
			}

		case ch == '|':
			l.next()
			if l.hasMore() && l.current() == '|' {
				l.next()
				tokens = append(tokens, Token{Type: "LOGICAL_OR", Value: "||", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "BITWISE_OR", Value: "|", Line: line, Column: column})
			}

		// Tokens simples
		case ch == '(':
			l.next()
			tokens = append(tokens, Token{Type: "LPAREN", Value: "(", Line: line, Column: column})
		case ch == ')':
			l.next()
			tokens = append(tokens, Token{Type: "RPAREN", Value: ")", Line: line, Column: column})
		case ch == '{':
			l.next()
			tokens = append(tokens, Token{Type: "LBRACE", Value: "{", Line: line, Column: column})
		case ch == '}':
			l.next()
			tokens = append(tokens, Token{Type: "RBRACE", Value: "}", Line: line, Column: column})
		case ch == '[':
			l.next()
			tokens = append(tokens, Token{Type: "LBRACKET", Value: "[", Line: line, Column: column})
		case ch == ']':
			l.next()
			tokens = append(tokens, Token{Type: "RBRACKET", Value: "]", Line: line, Column: column})
		case ch == ';':
			l.next()
			tokens = append(tokens, Token{Type: "SEMICOLON", Value: ";", Line: line, Column: column})
		case ch == ',':
			l.next()
			tokens = append(tokens, Token{Type: "COMMA", Value: ",", Line: line, Column: column})
		case ch == '.':
			l.next()
			tokens = append(tokens, Token{Type: "DOT", Value: ".", Line: line, Column: column})
		case ch == ':':
			l.next()
			tokens = append(tokens, Token{Type: "COLON", Value: ":", Line: line, Column: column})
		case ch == '?':
			l.next()
			tokens = append(tokens, Token{Type: "QUESTION", Value: "?", Line: line, Column: column})

		default:
			l.next()
			tokens = append(tokens, Token{Type: "UNKNOWN", Value: string(ch), Line: line, Column: column})
		}
	}

	return tokens
}

// Parser simplificado
func parseToAST(tokens []Token) (map[string]interface{}, []string) {
	ast := make(map[string]interface{})
	var errors []string
	
	// AST básico con estructura simple
	statements := make([]map[string]interface{}, 0)
	
	// Análisis básico sin recursión compleja
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		
		if token.Type == "KEYWORD" {
			switch token.Value {
			case "let", "const", "var":
				stmt := map[string]interface{}{
					"type": "VariableDeclaration",
					"kind": token.Value,
					"line": token.Line,
				}
				statements = append(statements, stmt)
				
			case "function":
				stmt := map[string]interface{}{
					"type": "FunctionDeclaration",
					"line": token.Line,
				}
				statements = append(statements, stmt)
				
			case "if", "for", "while":
				stmt := map[string]interface{}{
					"type": token.Value + "Statement",
					"line": token.Line,
				}
				statements = append(statements, stmt)
			}
		}
	}
	
	ast["type"] = "Program"
	ast["body"] = statements
	
	return ast, errors
}

// Análisis semántico simplificado
func performSemanticAnalysis(tokens []Token) []string {
	var errors []string
	declaredVars := make(map[string]bool)
	declaredFunctions := make(map[string]bool)
	
	// Primera pasada: buscar declaraciones de variables y funciones
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		
		// Declaraciones de variables
		if token.Type == "KEYWORD" && 
		   (token.Value == "let" || token.Value == "const" || token.Value == "var") {
			if i+1 < len(tokens) && tokens[i+1].Type == "IDENTIFIER" {
				declaredVars[tokens[i+1].Value] = true
			}
		}
		
		// Declaraciones de funciones
		if token.Type == "KEYWORD" && token.Value == "function" {
			if i+1 < len(tokens) && tokens[i+1].Type == "IDENTIFIER" {
				functionName := tokens[i+1].Value
				declaredFunctions[functionName] = true
				
				// Buscar parámetros de la función
				j := i + 2
				
				// Buscar el paréntesis de apertura
				for j < len(tokens) && tokens[j].Type != "LPAREN" {
					j++
				}
				j++ // Saltar LPAREN
				
				// Leer parámetros hasta RPAREN
				for j < len(tokens) && tokens[j].Type != "RPAREN" {
					if tokens[j].Type == "IDENTIFIER" {
						declaredVars[tokens[j].Value] = true // Los parámetros son variables locales
					}
					j++
				}
			}
		}
		
		// Variables en bucles for
		if token.Type == "KEYWORD" && token.Value == "for" {
			// Buscar declaraciones dentro del for (let i = ...)
			j := i + 1
			for j < len(tokens) && tokens[j].Type != "RPAREN" {
				if tokens[j].Type == "KEYWORD" && 
				   (tokens[j].Value == "let" || tokens[j].Value == "const" || tokens[j].Value == "var") {
					if j+1 < len(tokens) && tokens[j+1].Type == "IDENTIFIER" {
						declaredVars[tokens[j+1].Value] = true
					}
				}
				j++
			}
		}
	}
	
	// Segunda pasada: verificar uso de variables no declaradas
	for i, token := range tokens {
		if token.Type == "IDENTIFIER" && !isKeyword(token.Value) && !isBuiltIn(token.Value) {
			// Verificar si es parte de console.log, console.error, etc.
			if isPartOfConsoleMethod(tokens, i) {
				continue
			}
			
			// Verificar si es parte de require(), module.exports, etc.
			if isPartOfNodeJSPattern(tokens, i) {
				continue
			}
			
			// Verificar si es una declaración de función (saltarla)
			if isPartOfFunctionDeclaration(tokens, i) {
				continue
			}
			
			// Verificar si es una llamada a función declarada
			if declaredFunctions[token.Value] {
				continue
			}
			
			// Verificar si es una variable declarada
			if !declaredVars[token.Value] {
				errors = append(errors, fmt.Sprintf("Variable '%s' used but not declared at line %d", token.Value, token.Line))
			}
		}
	}
	
	// Verificar patrones específicos de Node.js
	for i := 0; i < len(tokens)-2; i++ {
		// Verificar require()
		if tokens[i].Value == "require" && i+1 < len(tokens) && tokens[i+1].Type != "LPAREN" {
			errors = append(errors, fmt.Sprintf("require must be followed by parentheses at line %d", tokens[i].Line))
		}
	}
	
	return errors
}

// Verificar si un token es parte de una declaración de función
func isPartOfFunctionDeclaration(tokens []Token, index int) bool {
	// Verificar si está después de 'function'
	if index >= 1 && 
	   tokens[index-1].Type == "KEYWORD" && 
	   tokens[index-1].Value == "function" {
		return true
	}
	
	// Verificar si está en la lista de parámetros de una función
	// Buscar hacia atrás para encontrar 'function'
	for i := index - 1; i >= 0; i-- {
		if tokens[i].Type == "KEYWORD" && tokens[i].Value == "function" {
			// Verificar si estamos entre paréntesis de la función
			parenCount := 0
			for j := i; j < index; j++ {
				if tokens[j].Type == "LPAREN" {
					parenCount++
				} else if tokens[j].Type == "RPAREN" {
					parenCount--
				}
			}
			if parenCount > 0 {
				return true // Estamos dentro de los paréntesis de parámetros
			}
		}
		// Si encontramos una llave de apertura, paramos la búsqueda
		if tokens[i].Type == "LBRACE" {
			break
		}
	}
	
	return false
}

// Verificar si un token es parte de un método de console
func isPartOfConsoleMethod(tokens []Token, index int) bool {
	// Verificar si es 'log', 'error', 'warn', etc. después de 'console.'
	if index >= 2 && 
	   tokens[index-2].Value == "console" && 
	   tokens[index-1].Type == "DOT" &&
	   isConsoleMethod(tokens[index].Value) {
		return true
	}
	return false
}

// Verificar si es un método válido de console
func isConsoleMethod(method string) bool {
	consoleMethods := []string{"log", "error", "warn", "info", "debug", "trace", "assert", "clear", "count", "time", "timeEnd"}
	for _, validMethod := range consoleMethods {
		if method == validMethod {
			return true
		}
	}
	return false
}

// Verificar si un token es parte de un patrón de Node.js
func isPartOfNodeJSPattern(tokens []Token, index int) bool {
	// Verificar module.exports
	if index >= 2 && 
	   tokens[index-2].Value == "module" && 
	   tokens[index-1].Type == "DOT" &&
	   tokens[index].Value == "exports" {
		return true
	}
	
	// Verificar process.env, process.argv, etc.
	if index >= 2 && 
	   tokens[index-2].Value == "process" && 
	   tokens[index-1].Type == "DOT" &&
	   isProcessProperty(tokens[index].Value) {
		return true
	}
	
	return false
}

// Verificar si es una propiedad válida de process
func isProcessProperty(property string) bool {
	processProps := []string{"env", "argv", "stdout", "stderr", "stdin", "pid", "platform", "version", "cwd", "exit"}
	for _, validProp := range processProps {
		if property == validProp {
			return true
		}
	}
	return false
}

func isKeyword(value string) bool {
	keywords := []string{"const", "let", "var", "function", "if", "else", "for", "while", "return", "true", "false", "null", "undefined"}
	for _, keyword := range keywords {
		if value == keyword {
			return true
		}
	}
	return false
}

func isBuiltIn(value string) bool {
	builtins := []string{"console", "require", "module", "exports", "process", "global", "__dirname", "__filename"}
	for _, builtin := range builtins {
		if value == builtin {
			return true
		}
	}
	return false
}

// Handlers HTTP
func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Límite de tamaño de código para evitar problemas
	if len(req.Code) > 50000 {
		http.Error(w, "Code too large", http.StatusBadRequest)
		return
	}
	
	// Análisis Léxico
	lexer := NewLexer(req.Code)
	tokens := lexer.Tokenize()
	
	// Análisis Sintáctico (simplificado)
	ast, syntaxErrors := parseToAST(tokens)
	
	// Análisis Semántico
	semanticErrors := performSemanticAnalysis(tokens)
	
	result := AnalysisResult{
		Tokens:         tokens,
		SyntaxErrors:   syntaxErrors,
		SemanticErrors: semanticErrors,
		AST:            ast,
	}
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func main() {
	http.HandleFunc("/analyze", analyzeHandler)
	http.HandleFunc("/health", healthHandler)
	
	fmt.Println("Servidor iniciado en puerto 8080")
	fmt.Println("Endpoints disponibles:")
	fmt.Println("  POST /analyze - Analizar código Node.js")
	fmt.Println("  GET  /health  - Estado del servidor")
	
	log.Fatal(http.ListenAndServe(":8080", nil))
}