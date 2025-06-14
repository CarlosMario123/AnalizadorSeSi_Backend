package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
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

// Estructura para el contexto de análisis semántico mejorado
type SemanticContext struct {
	declaredVars       map[string][]VariableDeclaration // variable -> declaraciones con contexto
	declaredFunctions  map[string][]int // función -> [líneas donde se declara]
	usedVars          map[string][]int // variable -> [líneas donde se usa]
	variableTypes     map[string]string // variable -> tipo inferido
	currentScope      int
	scopes            []map[string]bool // stack de scopes
	scopeStack        []ScopeInfo       // información detallada de scopes
	errors            []string
	requireStatements []string          // módulos requeridos
	exportedItems     []string          // items exportados
}

// Información de scope
type ScopeInfo struct {
	scopeType    string // "global", "function", "block", "for"
	functionName string // nombre de la función si aplica
	startLine    int
}

// Declaración de variable con contexto
type VariableDeclaration struct {
	line       int
	scopeType  string
	functionName string
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
	hasDecimal := false
	
	for l.hasMore() {
		ch := l.current()
		if unicode.IsDigit(ch) {
			l.next()
		} else if ch == '.' && !hasDecimal {
			hasDecimal = true
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
		"if": true, "else": true, "for": true, "while": true, "do": true,
		"return": true, "true": true, "false": true, "null": true,
		"undefined": true, "console": true, "require": true,
		"module": true, "exports": true, "class": true, "extends": true,
		"import": true, "export": true, "from": true,
		"try": true, "catch": true, "finally": true, "throw": true,
		"new": true, "this": true, "super": true, "typeof": true,
		"instanceof": true, "in": true, "of": true, "delete": true,
		"void": true, "break": true, "continue": true, "switch": true,
		"case": true, "async": true, "await": true,
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
			if l.hasMore() && l.current() == '*' {
				l.next()
				if l.hasMore() && l.current() == '=' {
					l.next()
					tokens = append(tokens, Token{Type: "EXPONENT_ASSIGN", Value: "**=", Line: line, Column: column})
				} else {
					tokens = append(tokens, Token{Type: "EXPONENT", Value: "**", Line: line, Column: column})
				}
			} else if l.hasMore() && l.current() == '=' {
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

		case ch == '%':
			l.next()
			if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "MODULO_ASSIGN", Value: "%=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "MODULO", Value: "%", Line: line, Column: column})
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
			if l.hasMore() && l.current() == '<' {
				l.next()
				if l.hasMore() && l.current() == '=' {
					l.next()
					tokens = append(tokens, Token{Type: "LEFT_SHIFT_ASSIGN", Value: "<<=", Line: line, Column: column})
				} else {
					tokens = append(tokens, Token{Type: "LEFT_SHIFT", Value: "<<", Line: line, Column: column})
				}
			} else if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "LESS_EQUAL", Value: "<=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "LESS", Value: "<", Line: line, Column: column})
			}

		case ch == '>':
			l.next()
			if l.hasMore() && l.current() == '>' {
				l.next()
				if l.hasMore() && l.current() == '>' {
					l.next()
					if l.hasMore() && l.current() == '=' {
						l.next()
						tokens = append(tokens, Token{Type: "UNSIGNED_RIGHT_SHIFT_ASSIGN", Value: ">>>=", Line: line, Column: column})
					} else {
						tokens = append(tokens, Token{Type: "UNSIGNED_RIGHT_SHIFT", Value: ">>>", Line: line, Column: column})
					}
				} else if l.hasMore() && l.current() == '=' {
					l.next()
					tokens = append(tokens, Token{Type: "RIGHT_SHIFT_ASSIGN", Value: ">>=", Line: line, Column: column})
				} else {
					tokens = append(tokens, Token{Type: "RIGHT_SHIFT", Value: ">>", Line: line, Column: column})
				}
			} else if l.hasMore() && l.current() == '=' {
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
			} else if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "BITWISE_AND_ASSIGN", Value: "&=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "BITWISE_AND", Value: "&", Line: line, Column: column})
			}

		case ch == '|':
			l.next()
			if l.hasMore() && l.current() == '|' {
				l.next()
				tokens = append(tokens, Token{Type: "LOGICAL_OR", Value: "||", Line: line, Column: column})
			} else if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "BITWISE_OR_ASSIGN", Value: "|=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "BITWISE_OR", Value: "|", Line: line, Column: column})
			}

		case ch == '^':
			l.next()
			if l.hasMore() && l.current() == '=' {
				l.next()
				tokens = append(tokens, Token{Type: "BITWISE_XOR_ASSIGN", Value: "^=", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "BITWISE_XOR", Value: "^", Line: line, Column: column})
			}

		case ch == '~':
			l.next()
			tokens = append(tokens, Token{Type: "BITWISE_NOT", Value: "~", Line: line, Column: column})

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
			if l.hasMore() && l.current() == '.' {
				l.next()
				if l.hasMore() && l.current() == '.' {
					l.next()
					tokens = append(tokens, Token{Type: "SPREAD", Value: "...", Line: line, Column: column})
				} else {
					// Error: .. no es válido
					tokens = append(tokens, Token{Type: "UNKNOWN", Value: "..", Line: line, Column: column})
				}
			} else {
				tokens = append(tokens, Token{Type: "DOT", Value: ".", Line: line, Column: column})
			}
		case ch == ':':
			l.next()
			tokens = append(tokens, Token{Type: "COLON", Value: ":", Line: line, Column: column})
		case ch == '?':
			l.next()
			if l.hasMore() && l.current() == '?' {
				l.next()
				tokens = append(tokens, Token{Type: "NULLISH_COALESCING", Value: "??", Line: line, Column: column})
			} else if l.hasMore() && l.current() == '.' {
				l.next()
				tokens = append(tokens, Token{Type: "OPTIONAL_CHAINING", Value: "?.", Line: line, Column: column})
			} else {
				tokens = append(tokens, Token{Type: "QUESTION", Value: "?", Line: line, Column: column})
			}

		default:
			l.next()
			tokens = append(tokens, Token{Type: "UNKNOWN", Value: string(ch), Line: line, Column: column})
		}
	}

	return tokens
}

// Parser mejorado
func parseToAST(tokens []Token) (map[string]interface{}, []string) {
	ast := make(map[string]interface{})
	var errors []string
	
	statements := make([]map[string]interface{}, 0)
	
	// Análisis mejorado con verificación de sintaxis
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
				
			case "for":
				stmt := map[string]interface{}{
					"type": "ForStatement",
					"line": token.Line,
				}
				statements = append(statements, stmt)
				forErrors := validateForLoopSyntax(tokens, i)
				errors = append(errors, forErrors...)
				
			case "while":
				stmt := map[string]interface{}{
					"type": "WhileStatement",
					"line": token.Line,
				}
				statements = append(statements, stmt)
				whileErrors := validateWhileLoopSyntax(tokens, i)
				errors = append(errors, whileErrors...)
				
				// Crear contexto temporal para validaciones avanzadas
				tempCtx := &SemanticContext{
					variableTypes: make(map[string]string),
					errors:       []string{},
				}
				// Inferir tipos desde el principio del archivo
				tempCtx.inferVariableTypes(tokens)
				// Validar lógica del while
				tempCtx.validateWhileLoopLogic(tokens, i)
				errors = append(errors, tempCtx.errors...)
				
			case "if":
				stmt := map[string]interface{}{
					"type": "IfStatement",
					"line": token.Line,
				}
				statements = append(statements, stmt)
				ifErrors := validateIfStatementSyntax(tokens, i)
				errors = append(errors, ifErrors...)
			}
		}
	}
	
	ast["type"] = "Program"
	ast["body"] = statements
	
	// Validaciones adicionales de sintaxis
	bracketErrors := validateBrackets(tokens)
	errors = append(errors, bracketErrors...)
	
	// Validar expresiones incompletas
	expressionErrors := validateExpressions(tokens)
	errors = append(errors, expressionErrors...)
	
	return ast, errors
}

// Validar expresiones incompletas y errores de sintaxis
func validateExpressions(tokens []Token) []string {
	var errors []string
	
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		
		// Detectar operadores incompletos (excluyendo contextos válidos)
		if token.Type == "IDENTIFIER" {
			if i+1 < len(tokens) {
				nextToken := tokens[i+1]
				
				// Caso: variable seguida de un solo +, -, *, / sin completar
				if nextToken.Type == "PLUS" || nextToken.Type == "MINUS" || 
				   nextToken.Type == "MULTIPLY" || nextToken.Type == "DIVIDE" {
					
					// Verificar si estamos dentro de paréntesis (expresión válida)
					if isInsideParentheses(tokens, i) {
						continue // Saltar validación si está en paréntesis
					}
					
					// Verificar si es una operación incompleta
					if i+2 >= len(tokens) {
						// Final del archivo con operador incompleto
						errors = append(errors, fmt.Sprintf("Incomplete expression: '%s %s' at line %d - missing operand", token.Value, nextToken.Value, token.Line))
					} else {
						nextNextToken := tokens[i+2]
						
						// Si lo que sigue no es un operando válido, es un error
						if !isValidOperand(nextNextToken) && !isValidContinuation(nextNextToken) {
							// Verificar si era un intento de incremento/decremento
							if nextToken.Type == "PLUS" && nextNextToken.Type != "PLUS" {
								errors = append(errors, fmt.Sprintf("Invalid expression: '%s +' at line %d - did you mean '%s++' (increment)?", token.Value, token.Line, token.Value))
							} else if nextToken.Type == "MINUS" && nextNextToken.Type != "MINUS" {
								errors = append(errors, fmt.Sprintf("Invalid expression: '%s -' at line %d - did you mean '%s--' (decrement)?", token.Value, token.Line, token.Value))
							} else {
								errors = append(errors, fmt.Sprintf("Incomplete expression: '%s %s' at line %d - missing operand", token.Value, nextToken.Value, token.Line))
							}
						}
					}
				}
			}
		}
		
		// Detectar operadores aislados (con mejor validación de contexto)
		if isArithmeticOperator(token.Type) {
			// Verificar si el operador tiene operandos válidos antes y después
			hasLeftOperand := false
			hasRightOperand := false
			
			if i > 0 {
				prevToken := tokens[i-1]
				hasLeftOperand = isValidOperand(prevToken) || prevToken.Type == "RPAREN"
			}
			
			if i+1 < len(tokens) {
				nextToken := tokens[i+1]
				hasRightOperand = isValidOperand(nextToken) || nextToken.Type == "LPAREN"
			}
			
			// Casos especiales para operadores unarios
			if token.Type == "PLUS" || token.Type == "MINUS" {
				// Pueden ser unarios al inicio de expresión o después de ciertos tokens
				if i == 0 || isStatementStart(tokens[i-1].Type) || tokens[i-1].Type == "LPAREN" {
					if !hasRightOperand {
						errors = append(errors, fmt.Sprintf("Unary operator '%s' missing operand at line %d", token.Value, token.Line))
					}
					continue
				}
			}
			
			// Operadores binarios requieren ambos operandos (con excepciones)
			if !hasLeftOperand && !hasRightOperand {
				// Solo reportar si no estamos en un contexto válido
				if !isInsideParentheses(tokens, i) {
					errors = append(errors, fmt.Sprintf("Operator '%s' missing both operands at line %d", token.Value, token.Line))
				}
			}
		}
		
		// Detectar asignaciones incompletas
		if token.Type == "ASSIGN" {
			if i+1 >= len(tokens) {
				errors = append(errors, fmt.Sprintf("Assignment operator '=' missing value at line %d", token.Line))
			} else if i == 0 {
				errors = append(errors, fmt.Sprintf("Assignment operator '=' missing variable at line %d", token.Line))
			}
		}
		
		// Detectar declaraciones de variables incompletas
		if token.Type == "KEYWORD" && (token.Value == "let" || token.Value == "const" || token.Value == "var") {
			if i+1 >= len(tokens) {
				errors = append(errors, fmt.Sprintf("Variable declaration '%s' missing identifier at line %d", token.Value, token.Line))
			} else if tokens[i+1].Type != "IDENTIFIER" {
				errors = append(errors, fmt.Sprintf("Variable declaration '%s' must be followed by identifier at line %d", token.Value, token.Line))
			}
		}
	}
	
	return errors
}

// Verificar si estamos dentro de paréntesis
func isInsideParentheses(tokens []Token, index int) bool {
	parenDepth := 0
	
	// Buscar hacia atrás para encontrar paréntesis de apertura
	for i := index - 1; i >= 0; i-- {
		if tokens[i].Type == "RPAREN" {
			parenDepth++
		} else if tokens[i].Type == "LPAREN" {
			if parenDepth == 0 {
				return true // Encontramos el paréntesis de apertura
			}
			parenDepth--
		} else if tokens[i].Type == "SEMICOLON" || tokens[i].Type == "LBRACE" {
			break // Salimos del contexto actual
		}
	}
	
	return false
}

// Verificar si un token es una continuación válida de expresión
func isValidContinuation(token Token) bool {
	return token.Type == "RPAREN" || token.Type == "SEMICOLON" || 
		   token.Type == "COMMA" || token.Type == "RBRACE" ||
		   token.Type == "RBRACKET" || isArithmeticOperator(token.Type)
}

// Verificar si un token es un operando válido
func isValidOperand(token Token) bool {
	return token.Type == "IDENTIFIER" || token.Type == "NUMBER" || 
		   token.Type == "STRING" || token.Type == "TEMPLATE_LITERAL" ||
		   (token.Type == "KEYWORD" && (token.Value == "true" || token.Value == "false" || 
		    token.Value == "null" || token.Value == "undefined")) ||
		   token.Type == "LPAREN" || token.Type == "LBRACKET" || token.Type == "LBRACE"
}

// Verificar si un token es un operador aritmético
func isArithmeticOperator(tokenType string) bool {
	return tokenType == "PLUS" || tokenType == "MINUS" || 
		   tokenType == "MULTIPLY" || tokenType == "DIVIDE" || 
		   tokenType == "MODULO" || tokenType == "EXPONENT"
}

// Verificar si un token indica el inicio de una declaración
func isStatementStart(tokenType string) bool {
	return tokenType == "LBRACE" || tokenType == "SEMICOLON" || 
		   tokenType == "LPAREN" || tokenType == "COMMA"
}

// Extraer contenido entre paréntesis
func extractParenthesesContent(tokens []Token, parenStart int) []Token {
	if parenStart >= len(tokens) || tokens[parenStart].Type != "LPAREN" {
		return nil
	}
	
	parenEnd := -1
	parenCount := 1
	
	for i := parenStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LPAREN" {
			parenCount++
		} else if tokens[i].Type == "RPAREN" {
			parenCount--
			if parenCount == 0 {
				parenEnd = i
				break
			}
		}
	}
	
	if parenEnd == -1 {
		return nil
	}
	
	if parenEnd <= parenStart + 1 {
		return []Token{} // Paréntesis vacíos
	}
	
	return tokens[parenStart+1 : parenEnd]
}

// Validar sintaxis del bucle while
func validateWhileLoopSyntax(tokens []Token, whileIndex int) []string {
	var errors []string
	
	// Buscar el paréntesis de apertura
	parenStart := -1
	for i := whileIndex + 1; i < len(tokens) && i < whileIndex + 5; i++ {
		if tokens[i].Type == "LPAREN" {
			parenStart = i
			break
		}
	}
	
	if parenStart == -1 {
		errors = append(errors, fmt.Sprintf("Missing opening parenthesis after 'while' at line %d", tokens[whileIndex].Line))
		return errors
	}
	
	// Buscar el paréntesis de cierre
	parenEnd := -1
	parenCount := 1
	for i := parenStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LPAREN" {
			parenCount++
		} else if tokens[i].Type == "RPAREN" {
			parenCount--
			if parenCount == 0 {
				parenEnd = i
				break
			}
		}
	}
	
	if parenEnd == -1 {
		errors = append(errors, fmt.Sprintf("Missing closing parenthesis for 'while' loop at line %d", tokens[whileIndex].Line))
		return errors
	}
	
	// Validar la condición
	conditionTokens := tokens[parenStart+1 : parenEnd]
	if len(conditionTokens) == 0 {
		errors = append(errors, fmt.Sprintf("Empty condition in while loop at line %d", tokens[whileIndex].Line))
	} else {
		condErrors := validateBooleanCondition(conditionTokens, "while", tokens[whileIndex].Line)
		errors = append(errors, condErrors...)
	}
	
	return errors
}

// Validar sintaxis del if
func validateIfStatementSyntax(tokens []Token, ifIndex int) []string {
	var errors []string
	
	// Buscar el paréntesis de apertura
	parenStart := -1
	for i := ifIndex + 1; i < len(tokens) && i < ifIndex + 5; i++ {
		if tokens[i].Type == "LPAREN" {
			parenStart = i
			break
		}
	}
	
	if parenStart == -1 {
		errors = append(errors, fmt.Sprintf("Missing opening parenthesis after 'if' at line %d", tokens[ifIndex].Line))
		return errors
	}
	
	// Buscar el paréntesis de cierre
	parenEnd := -1
	parenCount := 1
	for i := parenStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LPAREN" {
			parenCount++
		} else if tokens[i].Type == "RPAREN" {
			parenCount--
			if parenCount == 0 {
				parenEnd = i
				break
			}
		}
	}
	
	if parenEnd == -1 {
		errors = append(errors, fmt.Sprintf("Missing closing parenthesis for 'if' statement at line %d", tokens[ifIndex].Line))
		return errors
	}
	
	// Validar la condición con análisis de tipos
	conditionTokens := tokens[parenStart+1 : parenEnd]
	if len(conditionTokens) == 0 {
		errors = append(errors, fmt.Sprintf("Empty condition in if statement at line %d", tokens[ifIndex].Line))
	} else {
		// Crear contexto temporal para validación de tipos
		tempCtx := &SemanticContext{
			variableTypes: make(map[string]string),
			errors:       []string{},
		}
		
		// Inferir tipos desde el principio del archivo
		tempCtx.inferVariableTypes(tokens)
		
		// Validar condición booleana con análisis de tipos
		condErrors := validateBooleanConditionWithTypes(conditionTokens, "if", tokens[ifIndex].Line, tempCtx)
		errors = append(errors, condErrors...)
	}
	
	return errors
}

// Validar condición booleana con análisis de tipos mejorado
func validateBooleanConditionWithTypes(tokens []Token, context string, line int, ctx *SemanticContext) []string {
	var errors []string
	
	if len(tokens) == 0 {
		return errors
	}
	
	// Verificar operadores de comparación y tipos
	hasComparison := false
	hasLogicalOp := false
	hasValidBoolean := false
	
	for i, token := range tokens {
		switch token.Type {
		case "EQUAL", "NOT_EQUAL", "STRICT_EQUAL", "STRICT_NOT_EQUAL":
			hasComparison = true
			// Verificar coherencia de tipos en la comparación
			if i > 0 && i < len(tokens)-1 {
				leftVar := tokens[i-1]
				rightVar := tokens[i+1]
				ctx.validateComparisonTypes(leftVar, rightVar, token.Value, line)
			}
		case "LESS", "GREATER", "LESS_EQUAL", "GREATER_EQUAL":
			hasComparison = true
			// Verificar que sea comparación numérica válida
			if i > 0 && i < len(tokens)-1 {
				leftVar := tokens[i-1]
				rightVar := tokens[i+1]
				ctx.validateNumericalComparison(leftVar, rightVar, token.Value, line)
			}
		case "LOGICAL_AND", "LOGICAL_OR":
			hasLogicalOp = true
		case "KEYWORD":
			if token.Value == "true" || token.Value == "false" {
				hasValidBoolean = true
			}
		case "IDENTIFIER":
			// Verificar si es una variable que probablemente sea booleana
			if isBooleanLikeIdentifier(token.Value) {
				hasValidBoolean = true
			}
		case "NOT":
			// El operador ! indica una expresión booleana
			hasValidBoolean = true
		case "NUMBER":
			// Números por sí solos no son buenas condiciones booleanas
			if len(tokens) == 1 {
				errors = append(errors, fmt.Sprintf("Using number '%s' as boolean condition in %s statement at line %d is not recommended", token.Value, context, line))
			}
		case "STRING":
			// Strings por sí solos no son buenas condiciones booleanas
			if len(tokens) == 1 {
				errors = append(errors, fmt.Sprintf("Using string as boolean condition in %s statement at line %d is not recommended", context, line))
			}
		}
		
		// Verificar asignación accidental en condición
		if token.Type == "ASSIGN" && i > 0 && i < len(tokens)-1 {
			errors = append(errors, fmt.Sprintf("Assignment (=) found in %s condition at line %d, did you mean comparison (==) or (===)?", context, line))
		}
	}
	
	// Agregar errores del contexto de validación
	errors = append(errors, ctx.errors...)
	
	// Si no hay comparación, operador lógico, o boolean explícito, puede ser problemático
	if !hasComparison && !hasLogicalOp && !hasValidBoolean && len(tokens) == 1 {
		firstToken := tokens[0]
		if firstToken.Type == "IDENTIFIER" && !isBooleanLikeIdentifier(firstToken.Value) {
			errors = append(errors, fmt.Sprintf("Variable '%s' used as boolean condition in %s statement at line %d - consider explicit comparison", firstToken.Value, context, line))
		}
	}
	
	return errors
}

// Validar que una condición sea booleana válida (versión mejorada con análisis de tipos)
func validateBooleanCondition(tokens []Token, context string, line int) []string {
	var errors []string
	
	if len(tokens) == 0 {
		return errors
	}
	
	// Crear un contexto temporal para analizar tipos en esta condición
	tempCtx := &SemanticContext{
		variableTypes: make(map[string]string),
		errors:       []string{},
	}
	
	// Inferir tipos de variables si no están disponibles globalmente
	tempCtx.inferVariableTypes(tokens)
	
	// Verificar operadores de comparación válidos
	hasComparison := false
	hasLogicalOp := false
	hasValidBoolean := false
	
	for i, token := range tokens {
		switch token.Type {
		case "EQUAL", "NOT_EQUAL", "STRICT_EQUAL", "STRICT_NOT_EQUAL":
			hasComparison = true
			// Verificar coherencia de tipos en la comparación
			if i > 0 && i < len(tokens)-1 {
				leftVar := tokens[i-1]
				rightVar := tokens[i+1]
				tempCtx.validateComparisonTypes(leftVar, rightVar, token.Value, line)
			}
		case "LESS", "GREATER", "LESS_EQUAL", "GREATER_EQUAL":
			hasComparison = true
			// Verificar que sea comparación numérica válida
			if i > 0 && i < len(tokens)-1 {
				leftVar := tokens[i-1]
				rightVar := tokens[i+1]
				tempCtx.validateNumericalComparison(leftVar, rightVar, token.Value, line)
			}
		case "LOGICAL_AND", "LOGICAL_OR":
			hasLogicalOp = true
		case "KEYWORD":
			if token.Value == "true" || token.Value == "false" {
				hasValidBoolean = true
			}
		case "IDENTIFIER":
			// Verificar si es una variable que probablemente sea booleana
			if isBooleanLikeIdentifier(token.Value) {
				hasValidBoolean = true
			}
		case "NOT":
			// El operador ! indica una expresión booleana
			hasValidBoolean = true
		case "NUMBER":
			// Números por sí solos no son buenas condiciones booleanas
			if len(tokens) == 1 {
				errors = append(errors, fmt.Sprintf("Using number '%s' as boolean condition in %s statement at line %d is not recommended", token.Value, context, line))
			}
		case "STRING":
			// Strings por sí solos no son buenas condiciones booleanas
			if len(tokens) == 1 {
				errors = append(errors, fmt.Sprintf("Using string as boolean condition in %s statement at line %d is not recommended", context, line))
			}
		}
		
		// Verificar asignación accidental en condición
		if token.Type == "ASSIGN" && i > 0 && i < len(tokens)-1 {
			errors = append(errors, fmt.Sprintf("Assignment (=) found in %s condition at line %d, did you mean comparison (==) or (===)?", context, line))
		}
	}
	
	// Agregar errores del contexto temporal
	errors = append(errors, tempCtx.errors...)
	
	// Si no hay comparación, operador lógico, o boolean explícito, puede ser problemático
	if !hasComparison && !hasLogicalOp && !hasValidBoolean && len(tokens) == 1 {
		firstToken := tokens[0]
		if firstToken.Type == "IDENTIFIER" && !isBooleanLikeIdentifier(firstToken.Value) {
			errors = append(errors, fmt.Sprintf("Variable '%s' used as boolean condition in %s statement at line %d - consider explicit comparison", firstToken.Value, context, line))
		}
	}
	
	return errors
}

// Validar tipos en comparaciones numéricas
func (ctx *SemanticContext) validateNumericalComparison(leftToken, rightToken Token, operator string, line int) {
	leftType := ctx.getTokenType(leftToken)
	rightType := ctx.getTokenType(rightToken)
	
	// Verificar comparaciones problemáticas
	if leftType == "string" && rightType == "number" {
		errors := fmt.Sprintf("Comparing string variable '%s' with number using '%s' at line %d - this may cause unexpected behavior", leftToken.Value, operator, line)
		ctx.errors = append(ctx.errors, errors)
		
		// Verificar si es un string vacío comparado con número (caso muy problemático)
		if ctx.isEmptyStringVariable(leftToken.Value) {
			ctx.errors = append(ctx.errors, fmt.Sprintf("Variable '%s' is initialized as empty string but compared with number at line %d - this will always be false or cause type coercion", leftToken.Value, line))
		}
	} else if leftType == "number" && rightType == "string" {
		errors := fmt.Sprintf("Comparing number with string variable '%s' using '%s' at line %d - this may cause unexpected behavior", rightToken.Value, operator, line)
		ctx.errors = append(ctx.errors, errors)
		
		if ctx.isEmptyStringVariable(rightToken.Value) {
			ctx.errors = append(ctx.errors, fmt.Sprintf("Variable '%s' is initialized as empty string but compared with number at line %d - this will always be false or cause type coercion", rightToken.Value, line))
		}
	} else if leftType == "string" && rightType == "string" {
		// Comparación alfabética, advertir si parece que debería ser numérica
		if ctx.looksLikeNumericComparison(leftToken, rightToken, operator) {
			ctx.errors = append(ctx.errors, fmt.Sprintf("String comparison using '%s' at line %d - if comparing numbers, convert to numeric type first", operator, line))
		}
	} else if leftType == "string" && (operator == "<" || operator == ">" || operator == "<=" || operator == ">=") {
		// String comparado con número usando operadores numéricos
		if rightToken.Type == "NUMBER" {
			ctx.errors = append(ctx.errors, fmt.Sprintf("Comparing string variable '%s' with number %s using '%s' at line %d - string will be coerced to number", leftToken.Value, rightToken.Value, operator, line))
		}
	} else if rightType == "string" && (operator == "<" || operator == ">" || operator == "<=" || operator == ">=") {
		// Número comparado con string usando operadores numéricos
		if leftToken.Type == "NUMBER" {
			ctx.errors = append(ctx.errors, fmt.Sprintf("Comparing number %s with string variable '%s' using '%s' at line %d - string will be coerced to number", leftToken.Value, rightToken.Value, operator, line))
		}
	}
}

// Verificar si una variable fue inicializada como string vacío
func (ctx *SemanticContext) isEmptyStringVariable(varName string) bool {
	if varType, exists := ctx.variableTypes[varName]; exists {
		return varType == "empty_string"
	}
	return false
}

// Validar bucles while para detectar bucles infinitos o lógica problemática
func (ctx *SemanticContext) validateWhileLoopLogic(tokens []Token, whileIndex int) {
	// Encontrar la condición del while
	parenStart := -1
	for i := whileIndex + 1; i < len(tokens) && i < whileIndex + 5; i++ {
		if tokens[i].Type == "LPAREN" {
			parenStart = i
			break
		}
	}
	
	if parenStart == -1 {
		return
	}
	
	parenEnd := -1
	parenCount := 1
	for i := parenStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LPAREN" {
			parenCount++
		} else if tokens[i].Type == "RPAREN" {
			parenCount--
			if parenCount == 0 {
				parenEnd = i
				break
			}
		}
	}
	
	if parenEnd == -1 {
		return
	}
	
	// Analizar la condición
	conditionTokens := tokens[parenStart+1 : parenEnd]
	
	// Encontrar el cuerpo del while
	braceStart := -1
	for i := parenEnd + 1; i < len(tokens) && i < parenEnd + 5; i++ {
		if tokens[i].Type == "LBRACE" {
			braceStart = i
			break
		}
	}
	
	if braceStart == -1 {
		return
	}
	
	braceEnd := -1
	braceCount := 1
	for i := braceStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LBRACE" {
			braceCount++
		} else if tokens[i].Type == "RBRACE" {
			braceCount--
			if braceCount == 0 {
				braceEnd = i
				break
			}
		}
	}
	
	if braceEnd == -1 {
		return
	}
	
	bodyTokens := tokens[braceStart+1 : braceEnd]
	
	// Analizar variables en la condición y cómo se modifican en el cuerpo
	conditionVars := ctx.extractVariablesFromCondition(conditionTokens)
	
	for _, condVar := range conditionVars {
		// Verificar si la variable se modifica en el cuerpo del loop
		varModified := ctx.isVariableModifiedInBody(bodyTokens, condVar.name)
		varModificationType := ctx.getVariableModificationType(bodyTokens, condVar.name)
		
		if !varModified {
			ctx.errors = append(ctx.errors, fmt.Sprintf("Variable '%s' in while condition is never modified in loop body at line %d - potential infinite loop", condVar.name, tokens[whileIndex].Line))
		} else {
			// Verificar si la modificación es compatible con la condición
			ctx.validateLoopModificationLogic(condVar, varModificationType, tokens[whileIndex].Line)
		}
	}
}

// Estructura para información de variables en condiciones
type ConditionVariable struct {
	name         string
	operator     string
	compareValue string
	compareType  string
}

// Extraer variables de la condición del while
func (ctx *SemanticContext) extractVariablesFromCondition(tokens []Token) []ConditionVariable {
	var variables []ConditionVariable
	
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == "IDENTIFIER" {
			// Buscar operador de comparación después de la variable
			if i+1 < len(tokens) && ctx.isComparisonOperator(tokens[i+1].Type) {
				if i+2 < len(tokens) {
					variable := ConditionVariable{
						name:         tokens[i].Value,
						operator:     tokens[i+1].Value,
						compareValue: tokens[i+2].Value,
						compareType:  tokens[i+2].Type,
					}
					variables = append(variables, variable)
				}
			}
		}
	}
	
	return variables
}

// Verificar si es operador de comparación
func (ctx *SemanticContext) isComparisonOperator(tokenType string) bool {
	return tokenType == "LESS" || tokenType == "GREATER" || tokenType == "LESS_EQUAL" || 
		   tokenType == "GREATER_EQUAL" || tokenType == "EQUAL" || tokenType == "NOT_EQUAL" ||
		   tokenType == "STRICT_EQUAL" || tokenType == "STRICT_NOT_EQUAL"
}

// Verificar si una variable se modifica en el cuerpo del loop
func (ctx *SemanticContext) isVariableModifiedInBody(bodyTokens []Token, varName string) bool {
	for i := 0; i < len(bodyTokens); i++ {
		if bodyTokens[i].Type == "IDENTIFIER" && bodyTokens[i].Value == varName {
			// Verificar si hay asignación, incremento o decremento
			if i+1 < len(bodyTokens) {
				nextToken := bodyTokens[i+1]
				if nextToken.Type == "ASSIGN" || nextToken.Type == "PLUS_ASSIGN" || 
				   nextToken.Type == "MINUS_ASSIGN" || nextToken.Type == "INCREMENT" || 
				   nextToken.Type == "DECREMENT" {
					return true
				}
			}
			
			// Verificar incremento/decremento prefijo
			if i > 0 {
				prevToken := bodyTokens[i-1]
				if prevToken.Type == "INCREMENT" || prevToken.Type == "DECREMENT" {
					return true
				}
			}
		}
	}
	return false
}

// Obtener el tipo de modificación de la variable
func (ctx *SemanticContext) getVariableModificationType(bodyTokens []Token, varName string) string {
	for i := 0; i < len(bodyTokens); i++ {
		if bodyTokens[i].Type == "IDENTIFIER" && bodyTokens[i].Value == varName {
			if i+1 < len(bodyTokens) {
				nextToken := bodyTokens[i+1]
				switch nextToken.Type {
				case "INCREMENT":
					return "increment"
				case "DECREMENT":
					return "decrement"
				case "PLUS_ASSIGN":
					return "add_assign"
				case "MINUS_ASSIGN":
					return "subtract_assign"
				case "ASSIGN":
					return "assign"
				}
			}
			
			if i > 0 {
				prevToken := bodyTokens[i-1]
				if prevToken.Type == "INCREMENT" {
					return "pre_increment"
				} else if prevToken.Type == "DECREMENT" {
					return "pre_decrement"
				}
			}
		}
	}
	return "unknown"
}

// Validar lógica de modificación en loops
func (ctx *SemanticContext) validateLoopModificationLogic(condVar ConditionVariable, modificationType string, line int) {
	varType := ctx.variableTypes[condVar.name]
	
	// Caso problemático: variable string siendo incrementada
	if varType == "string" || varType == "empty_string" {
		if modificationType == "increment" || modificationType == "pre_increment" {
			ctx.errors = append(ctx.errors, fmt.Sprintf("String variable '%s' is being incremented (++) in while loop at line %d - this will convert to NaN and cause infinite loop", condVar.name, line))
		}
	}
	
	// Verificar dirección de modificación vs condición
	if condVar.operator == "<" || condVar.operator == "<=" {
		// Variable debería aumentar para alcanzar la condición
		if modificationType == "decrement" || modificationType == "pre_decrement" || modificationType == "subtract_assign" {
			ctx.errors = append(ctx.errors, fmt.Sprintf("Variable '%s' is decreasing but condition expects it to increase (%s) at line %d - potential infinite loop", condVar.name, condVar.operator, line))
		}
	} else if condVar.operator == ">" || condVar.operator == ">=" {
		// Variable debería disminuir para alcanzar la condición
		if modificationType == "increment" || modificationType == "pre_increment" || modificationType == "add_assign" {
			ctx.errors = append(ctx.errors, fmt.Sprintf("Variable '%s' is increasing but condition expects it to decrease (%s) at line %d - potential infinite loop", condVar.name, condVar.operator, line))
		}
	}
}

// Validar tipos en comparaciones de igualdad
func (ctx *SemanticContext) validateComparisonTypes(leftToken, rightToken Token, operator string, line int) {
	leftType := ctx.getTokenType(leftToken)
	rightType := ctx.getTokenType(rightToken)
	
	// Advertir sobre comparaciones de tipos diferentes con ==
	if (operator == "==" || operator == "!=") && leftType != "unknown" && rightType != "unknown" && leftType != rightType {
		ctx.errors = append(ctx.errors, fmt.Sprintf("Comparing different types (%s vs %s) with '%s' at line %d - consider using strict equality (%s==) instead", leftType, rightType, operator, line, operator[0:1]))
	}
}

// Obtener el tipo de un token
func (ctx *SemanticContext) getTokenType(token Token) string {
	switch token.Type {
	case "NUMBER":
		return "number"
	case "STRING", "TEMPLATE_LITERAL":
		// Verificar si es string vacío
		if token.Value == `""` || token.Value == `''` || strings.Trim(token.Value, `"'`) == "" {
			return "empty_string"
		}
		return "string"
	case "KEYWORD":
		if token.Value == "true" || token.Value == "false" {
			return "boolean"
		}
		if token.Value == "null" {
			return "null"
		}
		if token.Value == "undefined" {
			return "undefined"
		}
	case "IDENTIFIER":
		// Buscar en tipos inferidos
		if varType, exists := ctx.variableTypes[token.Value]; exists {
			return varType
		}
		// Si no lo encontramos, intentar inferir del nombre
		if isBooleanLikeIdentifier(token.Value) {
			return "boolean"
		}
	}
	return "unknown"
}

// Verificar si parece una comparación numérica
func (ctx *SemanticContext) looksLikeNumericComparison(leftToken, rightToken Token, operator string) bool {
	// Si ambos son identificadores que parecen números o contadores
	numericLikeNames := []string{"i", "j", "k", "index", "count", "num", "number", "length", "size", "total", "sum", "value", "val"}
	
	if leftToken.Type == "IDENTIFIER" && rightToken.Type == "IDENTIFIER" {
		leftIsNumeric := false
		rightIsNumeric := false
		
		for _, name := range numericLikeNames {
			if strings.Contains(strings.ToLower(leftToken.Value), name) {
				leftIsNumeric = true
			}
			if strings.Contains(strings.ToLower(rightToken.Value), name) {
				rightIsNumeric = true
			}
		}
		
		return leftIsNumeric || rightIsNumeric
	}
	
	return false
}

// Verificar si una declaración está dentro de un for loop
func isBooleanLikeIdentifier(name string) bool {
	booleanPrefixes := []string{"is", "has", "can", "should", "will", "was", "were", "are", "am"}
	booleanSuffixes := []string{"ed", "ing", "able", "ible"}
	booleanNames := []string{"flag", "enabled", "disabled", "active", "visible", "hidden", "valid", "invalid", "ready", "done", "complete", "finished", "started", "stopped", "paused", "running", "loading", "success", "error", "found", "exists", "available", "selected", "checked", "confirmed"}
	
	lowerName := strings.ToLower(name)
	
	// Verificar nombres completos
	for _, boolName := range booleanNames {
		if lowerName == boolName || strings.Contains(lowerName, boolName) {
			return true
		}
	}
	
	// Verificar prefijos
	for _, prefix := range booleanPrefixes {
		if strings.HasPrefix(lowerName, prefix) {
			return true
		}
	}
	
	// Verificar sufijos
	for _, suffix := range booleanSuffixes {
		if strings.HasSuffix(lowerName, suffix) {
			return true
		}
	}
	
	return false
}

// Validar sintaxis específica del bucle for
func validateForLoopSyntax(tokens []Token, forIndex int) []string {
	var errors []string
	
	// Buscar el paréntesis de apertura
	parenStart := -1
	for i := forIndex + 1; i < len(tokens) && i < forIndex + 5; i++ {
		if tokens[i].Type == "LPAREN" {
			parenStart = i
			break
		}
	}
	
	if parenStart == -1 {
		errors = append(errors, fmt.Sprintf("Missing opening parenthesis after 'for' at line %d", tokens[forIndex].Line))
		return errors
	}
	
	// Buscar el paréntesis de cierre
	parenEnd := -1
	parenCount := 1
	for i := parenStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LPAREN" {
			parenCount++
		} else if tokens[i].Type == "RPAREN" {
			parenCount--
			if parenCount == 0 {
				parenEnd = i
				break
			}
		}
	}
	
	if parenEnd == -1 {
		errors = append(errors, fmt.Sprintf("Missing closing parenthesis for 'for' loop at line %d", tokens[forIndex].Line))
		return errors
	}
	
	// Analizar el contenido entre paréntesis
	forContent := tokens[parenStart+1 : parenEnd]
	
	// Detectar si es for...in o for...of
	hasIn := false
	hasOf := false
	for _, token := range forContent {
		if token.Type == "KEYWORD" && token.Value == "in" {
			hasIn = true
		}
		if token.Type == "KEYWORD" && token.Value == "of" {
			hasOf = true
		}
	}
	
	if hasIn || hasOf {
		// Validar for...in o for...of
		errors = append(errors, validateForInOfSyntax(forContent, tokens[forIndex].Line, hasOf)...)
	} else {
		// Validar for tradicional (init; condition; update)
		errors = append(errors, validateTraditionalForSyntax(forContent, tokens[forIndex].Line)...)
	}
	
	return errors
}

// Validar for...in o for...of
func validateForInOfSyntax(tokens []Token, line int, isForOf bool) []string {
	var errors []string
	loopType := "for...in"
	if isForOf {
		loopType = "for...of"
	}
	
	// Debe tener la estructura: variable in/of iterable
	if len(tokens) < 3 {
		errors = append(errors, fmt.Sprintf("Invalid %s syntax at line %d", loopType, line))
		return errors
	}
	
	// Primer token debe ser declaración de variable o identificador
	if tokens[0].Type == "KEYWORD" && (tokens[0].Value == "let" || tokens[0].Value == "const" || tokens[0].Value == "var") {
		if len(tokens) < 4 || tokens[1].Type != "IDENTIFIER" {
			errors = append(errors, fmt.Sprintf("Missing variable name in %s at line %d", loopType, line))
		}
	} else if tokens[0].Type != "IDENTIFIER" {
		errors = append(errors, fmt.Sprintf("Expected variable declaration or identifier in %s at line %d", loopType, line))
	}
	
	return errors
}

// Validar for tradicional
func validateTraditionalForSyntax(tokens []Token, line int) []string {
	var errors []string
	
	// Contar puntos y comas (debería haber exactamente 2)
	semicolonCount := 0
	semicolonPositions := []int{}
	
	for i, token := range tokens {
		if token.Type == "SEMICOLON" {
			semicolonCount++
			semicolonPositions = append(semicolonPositions, i)
		}
	}
	
	if semicolonCount != 2 {
		if semicolonCount < 2 {
			errors = append(errors, fmt.Sprintf("Missing semicolon in for loop at line %d (expected 2, found %d)", line, semicolonCount))
		} else {
			errors = append(errors, fmt.Sprintf("Too many semicolons in for loop at line %d (expected 2, found %d)", line, semicolonCount))
		}
		return errors
	}
	
	// Verificar que cada sección tenga contenido apropiado
	if len(semicolonPositions) >= 2 {
		// Sección de inicialización
		initSection := tokens[0:semicolonPositions[0]]
		if len(initSection) == 0 {
			errors = append(errors, fmt.Sprintf("Empty initialization in for loop at line %d", line))
		}
		
		// Sección de condición
		conditionSection := tokens[semicolonPositions[0]+1:semicolonPositions[1]]
		if len(conditionSection) == 0 {
			errors = append(errors, fmt.Sprintf("Empty condition in for loop at line %d", line))
		} else {
			condErrors := validateBooleanCondition(conditionSection, "for", line)
			errors = append(errors, condErrors...)
		}
		
		// Sección de actualización
		updateSection := tokens[semicolonPositions[1]+1:]
		if len(updateSection) == 0 {
			errors = append(errors, fmt.Sprintf("Empty update expression in for loop at line %d", line))
		}
	}
	
	return errors
}

// Validar balanceado de llaves, paréntesis y corchetes
func validateBrackets(tokens []Token) []string {
	var errors []string
	
	type bracketInfo struct {
		tokenType string
		line      int
		column    int
	}
	
	var stack []bracketInfo
	
	bracketPairs := map[string]string{
		"LPAREN":   "RPAREN",
		"LBRACE":   "RBRACE",
		"LBRACKET": "RBRACKET",
	}
	
	closingToOpening := map[string]string{
		"RPAREN":   "LPAREN",
		"RBRACE":   "LBRACE",
		"RBRACKET": "LBRACKET",
	}
	
	for _, token := range tokens {
		if _, isOpening := bracketPairs[token.Type]; isOpening {
			stack = append(stack, bracketInfo{
				tokenType: token.Type,
				line:      token.Line,
				column:    token.Column,
			})
		} else if expectedOpening, isClosing := closingToOpening[token.Type]; isClosing {
			if len(stack) == 0 {
				errors = append(errors, fmt.Sprintf("Unexpected closing bracket '%s' at line %d:%d", token.Value, token.Line, token.Column))
			} else {
				top := stack[len(stack)-1]
				if top.tokenType != expectedOpening {
					errors = append(errors, fmt.Sprintf("Mismatched brackets: expected closing for '%s' at line %d:%d, but found '%s' at line %d:%d", 
						getBracketChar(top.tokenType), top.line, top.column, token.Value, token.Line, token.Column))
				}
				stack = stack[:len(stack)-1]
			}
		}
	}
	
	// Verificar llaves no cerradas
	for _, bracket := range stack {
		errors = append(errors, fmt.Sprintf("Unclosed bracket '%s' at line %d:%d", getBracketChar(bracket.tokenType), bracket.line, bracket.column))
	}
	
	return errors
}

func getBracketChar(tokenType string) string {
	switch tokenType {
	case "LPAREN":
		return "("
	case "LBRACE":
		return "{"
	case "LBRACKET":
		return "["
	default:
		return tokenType
	}
}

// Análisis semántico mejorado
func performSemanticAnalysis(tokens []Token) []string {
	ctx := &SemanticContext{
		declaredVars:      make(map[string][]VariableDeclaration),
		declaredFunctions: make(map[string][]int),
		usedVars:         make(map[string][]int),
		variableTypes:    make(map[string]string),
		scopes:           []map[string]bool{make(map[string]bool)}, // scope global
		scopeStack:       []ScopeInfo{{scopeType: "global", startLine: 1}},
		errors:           []string{},
		requireStatements: []string{},
		exportedItems:    []string{},
	}
	
	// Primera pasada: recopilar todas las declaraciones y tipos con contexto de scope
	ctx.collectDeclarationsWithScope(tokens)
	ctx.inferVariableTypes(tokens)
	
	// Segunda pasada: validar uso de variables
	ctx.validateVariableUsage(tokens)
	
	// Tercera pasada: validaciones específicas de Node.js
	ctx.validateNodeJSPatterns(tokens)
	
	// Validaciones adicionales
	ctx.validateDuplicateDeclarationsWithScope()
	ctx.validateRequireStatements()
	ctx.validateExports()
	ctx.validateAsyncAwait(tokens)
	ctx.validateArrowFunctions(tokens)
	ctx.validateDestructuring(tokens)
	
	return ctx.errors
}

// Recopilar declaraciones con información de scope
func (ctx *SemanticContext) collectDeclarationsWithScope(tokens []Token) {
	processedPositions := make(map[string]bool) // Para evitar duplicados
	
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		
		// Actualizar stack de scopes
		ctx.updateScopeStack(tokens, i)
		
		// Declaraciones de variables (excluyendo for loops que se procesan por separado)
		if token.Type == "KEYWORD" && (token.Value == "let" || token.Value == "const" || token.Value == "var") {
			if i+1 < len(tokens) && tokens[i+1].Type == "IDENTIFIER" {
				// Verificar si está dentro de un for loop
				if !ctx.isInsideForLoop(tokens, i) {
					varName := tokens[i+1].Value
					key := fmt.Sprintf("%s_%d_%d", varName, token.Line, i)
					if !processedPositions[key] {
						currentScope := ctx.getCurrentScope()
						declaration := VariableDeclaration{
							line:         token.Line,
							scopeType:    currentScope.scopeType,
							functionName: currentScope.functionName,
						}
						
						if ctx.declaredVars[varName] == nil {
							ctx.declaredVars[varName] = []VariableDeclaration{}
						}
						ctx.declaredVars[varName] = append(ctx.declaredVars[varName], declaration)
						processedPositions[key] = true
					}
				}
			}
		}
		
		// Declaraciones de funciones
		if token.Type == "KEYWORD" && token.Value == "function" {
			if i+1 < len(tokens) && tokens[i+1].Type == "IDENTIFIER" {
				funcName := tokens[i+1].Value
				key := fmt.Sprintf("func_%s_%d_%d", funcName, token.Line, i)
				if !processedPositions[key] {
					if ctx.declaredFunctions[funcName] == nil {
						ctx.declaredFunctions[funcName] = []int{}
					}
					ctx.declaredFunctions[funcName] = append(ctx.declaredFunctions[funcName], token.Line)
					processedPositions[key] = true
					
					// Agregar parámetros de función como variables declaradas
					ctx.collectFunctionParametersWithScope(tokens, i, funcName)
				}
			}
		}
		
		// Variables en destructuring
		if token.Type == "LBRACE" || token.Type == "LBRACKET" {
			ctx.collectDestructuringVariables(tokens, i)
		}
		
		// Variables en for loops (procesamiento especial)
		if token.Type == "KEYWORD" && token.Value == "for" {
			ctx.collectForLoopVariablesWithScope(tokens, i)
		}
		
		// Catch parameters
		if token.Type == "KEYWORD" && token.Value == "catch" {
			ctx.collectCatchParameters(tokens, i)
		}
	}
}

// Actualizar stack de scopes
func (ctx *SemanticContext) updateScopeStack(tokens []Token, index int) {
	token := tokens[index]
	
	// Detectar inicio de nuevo scope
	if token.Type == "KEYWORD" && token.Value == "function" {
		functionName := ""
		if index+1 < len(tokens) && tokens[index+1].Type == "IDENTIFIER" {
			functionName = tokens[index+1].Value
		}
		
		newScope := ScopeInfo{
			scopeType:    "function",
			functionName: functionName,
			startLine:    token.Line,
		}
		ctx.scopeStack = append(ctx.scopeStack, newScope)
	}
	
	// Detectar fin de scope (simplificado - en un analizador completo sería más complejo)
	if token.Type == "RBRACE" {
		// Verificar si es el final de una función
		if len(ctx.scopeStack) > 1 && ctx.scopeStack[len(ctx.scopeStack)-1].scopeType == "function" {
			ctx.scopeStack = ctx.scopeStack[:len(ctx.scopeStack)-1]
		}
	}
}

// Obtener scope actual
func (ctx *SemanticContext) getCurrentScope() ScopeInfo {
	if len(ctx.scopeStack) == 0 {
		return ScopeInfo{scopeType: "global", startLine: 1}
	}
	return ctx.scopeStack[len(ctx.scopeStack)-1]
}

// Recopilar parámetros de función con scope
func (ctx *SemanticContext) collectFunctionParametersWithScope(tokens []Token, funcIndex int, functionName string) {
	// Buscar paréntesis de parámetros
	parenStart := -1
	for i := funcIndex + 2; i < len(tokens) && i < funcIndex + 10; i++ {
		if tokens[i].Type == "LPAREN" {
			parenStart = i
			break
		}
	}
	
	if parenStart == -1 {
		return
	}
	
	// Buscar paréntesis de cierre
	parenEnd := -1
	parenCount := 1
	for i := parenStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LPAREN" {
			parenCount++
		} else if tokens[i].Type == "RPAREN" {
			parenCount--
			if parenCount == 0 {
				parenEnd = i
				break
			}
		}
	}
	
	if parenEnd == -1 {
		return
	}
	
	// Recopilar parámetros
	for i := parenStart + 1; i < parenEnd; i++ {
		if tokens[i].Type == "IDENTIFIER" {
			paramName := tokens[i].Value
			declaration := VariableDeclaration{
				line:         tokens[i].Line,
				scopeType:    "function",
				functionName: functionName,
			}
			
			if ctx.declaredVars[paramName] == nil {
				ctx.declaredVars[paramName] = []VariableDeclaration{}
			}
			ctx.declaredVars[paramName] = append(ctx.declaredVars[paramName], declaration)
		}
	}
}

// Recopilar variables de for loops con scope
func (ctx *SemanticContext) collectForLoopVariablesWithScope(tokens []Token, forIndex int) {
	parenStart := -1
	for i := forIndex + 1; i < len(tokens) && i < forIndex + 5; i++ {
		if tokens[i].Type == "LPAREN" {
			parenStart = i
			break
		}
	}
	
	if parenStart == -1 {
		return
	}
	
	parenEnd := -1
	parenCount := 1
	for i := parenStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LPAREN" {
			parenCount++
		} else if tokens[i].Type == "RPAREN" {
			parenCount--
			if parenCount == 0 {
				parenEnd = i
				break
			}
		}
	}
	
	if parenEnd == -1 {
		return
	}
	
	// Buscar declaraciones de variables en el for
	processedVars := make(map[string]bool)
	for i := parenStart + 1; i < parenEnd; i++ {
		if tokens[i].Type == "KEYWORD" && (tokens[i].Value == "let" || tokens[i].Value == "const" || tokens[i].Value == "var") {
			if i+1 < len(tokens) && tokens[i+1].Type == "IDENTIFIER" {
				varName := tokens[i+1].Value
				
				// Evitar duplicados dentro del mismo for loop
				if !processedVars[varName] {
					currentScope := ctx.getCurrentScope()
					declaration := VariableDeclaration{
						line:         tokens[i].Line,
						scopeType:    "for",
						functionName: currentScope.functionName,
					}
					
					if ctx.declaredVars[varName] == nil {
						ctx.declaredVars[varName] = []VariableDeclaration{}
					}
					ctx.declaredVars[varName] = append(ctx.declaredVars[varName], declaration)
					processedVars[varName] = true
				}
			}
		}
	}
}

// Validar declaraciones duplicadas con scope (corregido)
func (ctx *SemanticContext) validateDuplicateDeclarationsWithScope() {
	// Verificar variables declaradas múltiples veces en el mismo scope
	for varName, declarations := range ctx.declaredVars {
		if len(declarations) > 1 {
			// Agrupar por scope
			scopeGroups := make(map[string][]VariableDeclaration)
			
			for _, decl := range declarations {
				scopeKey := fmt.Sprintf("%s:%s", decl.scopeType, decl.functionName)
				if scopeGroups[scopeKey] == nil {
					scopeGroups[scopeKey] = []VariableDeclaration{}
				}
				scopeGroups[scopeKey] = append(scopeGroups[scopeKey], decl)
			}
			
			// Solo reportar duplicados dentro del mismo scope
			for scopeKey, scopeDeclarations := range scopeGroups {
				if len(scopeDeclarations) > 1 {
					var lines []int
					for _, decl := range scopeDeclarations {
						lines = append(lines, decl.line)
					}
					
					scopeDescription := ""
					if strings.HasPrefix(scopeKey, "function:") {
						functionName := strings.TrimPrefix(scopeKey, "function:")
						if functionName != "" {
							scopeDescription = fmt.Sprintf(" in function '%s'", functionName)
						} else {
							scopeDescription = " in function scope"
						}
					} else if strings.HasPrefix(scopeKey, "for:") {
						scopeDescription = " in for loop scope"
					}
					
					ctx.errors = append(ctx.errors, fmt.Sprintf("Variable '%s' declared multiple times%s at lines: %v", varName, scopeDescription, lines))
				}
			}
		}
	}
	
	// Verificar funciones declaradas múltiples veces (estas siempre son en scope global)
	for funcName, lines := range ctx.declaredFunctions {
		if len(lines) > 1 {
			uniqueLines := make(map[int]bool)
			var duplicateLines []int
			
			for _, line := range lines {
				if uniqueLines[line] {
					continue
				}
				uniqueLines[line] = true
				duplicateLines = append(duplicateLines, line)
			}
			
			if len(duplicateLines) > 1 {
				ctx.errors = append(ctx.errors, fmt.Sprintf("Function '%s' declared multiple times at lines: %v", funcName, duplicateLines))
			}
		}
	}
}

func (ctx *SemanticContext) isInsideForLoop(tokens []Token, declIndex int) bool {
	// Buscar hacia atrás para encontrar un 'for' reciente
	for i := declIndex - 1; i >= 0 && i >= declIndex-20; i-- {
		if tokens[i].Type == "KEYWORD" && tokens[i].Value == "for" {
			// Verificar si estamos dentro de los paréntesis del for
			parenStart := -1
			parenEnd := -1
			
			// Encontrar paréntesis del for
			for j := i + 1; j < len(tokens) && j < i + 10; j++ {
				if tokens[j].Type == "LPAREN" {
					parenStart = j
					break
				}
			}
			
			if parenStart != -1 {
				parenCount := 1
				for j := parenStart + 1; j < len(tokens); j++ {
					if tokens[j].Type == "LPAREN" {
						parenCount++
					} else if tokens[j].Type == "RPAREN" {
						parenCount--
						if parenCount == 0 {
							parenEnd = j
							break
						}
					}
				}
				
				// Verificar si declIndex está dentro del rango del for
				if parenEnd != -1 && declIndex > parenStart && declIndex < parenEnd {
					return true
				}
			}
		}
		
		// Si encontramos otro statement, paramos la búsqueda
		if tokens[i].Type == "SEMICOLON" || tokens[i].Type == "LBRACE" {
			break
		}
	}
	return false
}

// Recopilar variables de destructuring
func (ctx *SemanticContext) collectDestructuringVariables(tokens []Token, startIndex int) {
	// Verificar si es destructuring (debe estar después de let/const/var o =)
	isDestructuring := false
	if startIndex > 0 {
		prevToken := tokens[startIndex-1]
		if prevToken.Type == "KEYWORD" && (prevToken.Value == "let" || prevToken.Value == "const" || prevToken.Value == "var") {
			isDestructuring = true
		} else if prevToken.Type == "ASSIGN" {
			isDestructuring = true
		}
	}
	
	if !isDestructuring {
		return
	}
	
	// Encontrar el cierre del destructuring
	endIndex := -1
	bracketCount := 1
	openChar := tokens[startIndex].Type
	closeChar := "RBRACE"
	if openChar == "LBRACKET" {
		closeChar = "RBRACKET"
	}
	
	for i := startIndex + 1; i < len(tokens); i++ {
		if tokens[i].Type == openChar {
			bracketCount++
		} else if tokens[i].Type == closeChar {
			bracketCount--
			if bracketCount == 0 {
				endIndex = i
				break
			}
		}
	}
	
	if endIndex == -1 {
		return
	}
	
	// Recopilar variables del destructuring
	currentScope := ctx.getCurrentScope()
	for i := startIndex + 1; i < endIndex; i++ {
		if tokens[i].Type == "IDENTIFIER" {
			varName := tokens[i].Value
			if !isKeyword(varName) && !isBuiltIn(varName) {
				declaration := VariableDeclaration{
					line:         tokens[i].Line,
					scopeType:    currentScope.scopeType,
					functionName: currentScope.functionName,
				}
				
				if ctx.declaredVars[varName] == nil {
					ctx.declaredVars[varName] = []VariableDeclaration{}
				}
				ctx.declaredVars[varName] = append(ctx.declaredVars[varName], declaration)
			}
		}
	}
}

// Inferir tipos de variables basándose en sus asignaciones
func (ctx *SemanticContext) inferVariableTypes(tokens []Token) {
	for i := 0; i < len(tokens)-2; i++ {
		// Patrón: variable = valor
		if tokens[i].Type == "IDENTIFIER" && tokens[i+1].Type == "ASSIGN" && i+2 < len(tokens) {
			varName := tokens[i].Value
			valueToken := tokens[i+2]
			
			// Inferir tipo basándose en el valor asignado
			inferredType := ctx.inferTypeFromValue(valueToken)
			if inferredType != "unknown" {
				ctx.variableTypes[varName] = inferredType
			}
		}
		
		// Patrón: let/const/var variable = valor
		if tokens[i].Type == "KEYWORD" && (tokens[i].Value == "let" || tokens[i].Value == "const" || tokens[i].Value == "var") {
			if i+1 < len(tokens) && tokens[i+1].Type == "IDENTIFIER" {
				if i+2 < len(tokens) && tokens[i+2].Type == "ASSIGN" && i+3 < len(tokens) {
					varName := tokens[i+1].Value
					valueToken := tokens[i+3]
					
					inferredType := ctx.inferTypeFromValue(valueToken)
					if inferredType != "unknown" {
						ctx.variableTypes[varName] = inferredType
					}
				}
			}
		}
	}
}

// Inferir tipo desde un token de valor
func (ctx *SemanticContext) inferTypeFromValue(token Token) string {
	switch token.Type {
	case "NUMBER":
		return "number"
	case "STRING", "TEMPLATE_LITERAL":
		// Verificar si es string vacío
		if token.Value == `""` || token.Value == `''` || token.Value == `""` {
			return "empty_string"
		}
		return "string"
	case "KEYWORD":
		if token.Value == "true" || token.Value == "false" {
			return "boolean"
		}
		if token.Value == "null" {
			return "null"
		}
		if token.Value == "undefined" {
			return "undefined"
		}
	case "LBRACKET":
		return "array"
	case "LBRACE":
		return "object"
	}
	return "unknown"
}

// Recopilar parámetros de catch
func (ctx *SemanticContext) collectCatchParameters(tokens []Token, catchIndex int) {
	parenStart := -1
	for i := catchIndex + 1; i < len(tokens) && i < catchIndex + 5; i++ {
		if tokens[i].Type == "LPAREN" {
			parenStart = i
			break
		}
	}
	
	if parenStart == -1 {
		return
	}
	
	if parenStart + 1 < len(tokens) && tokens[parenStart + 1].Type == "IDENTIFIER" {
		errorParam := tokens[parenStart + 1].Value
		currentScope := ctx.getCurrentScope()
		declaration := VariableDeclaration{
			line:         tokens[parenStart + 1].Line,
			scopeType:    "catch",
			functionName: currentScope.functionName,
		}
		
		if ctx.declaredVars[errorParam] == nil {
			ctx.declaredVars[errorParam] = []VariableDeclaration{}
		}
		ctx.declaredVars[errorParam] = append(ctx.declaredVars[errorParam], declaration)
	}
}

// Validar uso de variables
func (ctx *SemanticContext) validateVariableUsage(tokens []Token) {
	for i, token := range tokens {
		if token.Type == "IDENTIFIER" && !isKeyword(token.Value) && !isBuiltIn(token.Value) {
			// Skip si es parte de patterns específicos
			if ctx.isPartOfSpecialPattern(tokens, i) {
				continue
			}
			
			// Skip si es una declaración
			if ctx.isPartOfDeclaration(tokens, i) {
				continue
			}
			
			// Registrar uso de variable
			varName := token.Value
			if ctx.usedVars[varName] == nil {
				ctx.usedVars[varName] = []int{}
			}
			ctx.usedVars[varName] = append(ctx.usedVars[varName], token.Line)
			
			// Verificar si la variable fue declarada
			if ctx.declaredVars[varName] == nil && ctx.declaredFunctions[varName] == nil {
				ctx.errors = append(ctx.errors, fmt.Sprintf("Variable '%s' used but not declared at line %d", varName, token.Line))
			}
		}
	}
}

// Verificar si es parte de un patrón especial
func (ctx *SemanticContext) isPartOfSpecialPattern(tokens []Token, index int) bool {
	// console.method
	if index >= 2 && tokens[index-2].Value == "console" && tokens[index-1].Type == "DOT" {
		return true
	}
	
	// module.exports, process.env, etc.
	if index >= 2 && tokens[index-1].Type == "DOT" {
		prevVar := tokens[index-2].Value
		if prevVar == "module" || prevVar == "process" || prevVar == "global" {
			return true
		}
	}
	
	// require()
	if tokens[index].Value == "require" {
		return true
	}
	
	// Después de new
	if index > 0 && tokens[index-1].Type == "KEYWORD" && tokens[index-1].Value == "new" {
		return true
	}
	
	// En import/export statements
	if ctx.isPartOfImportExport(tokens, index) {
		return true
	}
	
	return false
}

// Verificar si es parte de import/export
func (ctx *SemanticContext) isPartOfImportExport(tokens []Token, index int) bool {
	// Buscar hacia atrás para encontrar import/export
	for i := index - 1; i >= 0 && i >= index-10; i-- {
		if tokens[i].Type == "KEYWORD" {
			if tokens[i].Value == "import" || tokens[i].Value == "export" {
				return true
			}
			// Si encontramos otra keyword, paramos
			break
		}
		if tokens[i].Type == "SEMICOLON" || tokens[i].Type == "LBRACE" {
			break
		}
	}
	return false
}

// Verificar si es parte de una declaración
func (ctx *SemanticContext) isPartOfDeclaration(tokens []Token, index int) bool {
	// Después de let/const/var
	if index > 0 {
		prevToken := tokens[index-1]
		if prevToken.Type == "KEYWORD" && (prevToken.Value == "let" || prevToken.Value == "const" || prevToken.Value == "var") {
			return true
		}
	}
	
	// Después de function
	if index > 0 {
		prevToken := tokens[index-1]
		if prevToken.Type == "KEYWORD" && prevToken.Value == "function" {
			return true
		}
	}
	
	// En destructuring assignment
	if ctx.isInDestructuring(tokens, index) {
		return true
	}
	
	return false
}

// Verificar si está en destructuring
func (ctx *SemanticContext) isInDestructuring(tokens []Token, index int) bool {
	// Buscar hacia atrás para encontrar { o [ seguido de let/const/var
	bracketDepth := 0
	for i := index - 1; i >= 0; i-- {
		if tokens[i].Type == "RBRACE" || tokens[i].Type == "RBRACKET" {
			bracketDepth++
		} else if tokens[i].Type == "LBRACE" || tokens[i].Type == "LBRACKET" {
			if bracketDepth == 0 {
				// Verificar si hay let/const/var antes
				if i > 0 && tokens[i-1].Type == "KEYWORD" && 
				   (tokens[i-1].Value == "let" || tokens[i-1].Value == "const" || tokens[i-1].Value == "var") {
					return true
				}
				break
			}
			bracketDepth--
		}
	}
	return false
}

// Validar patrones específicos de Node.js
func (ctx *SemanticContext) validateNodeJSPatterns(tokens []Token) {
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		
		// Validar require()
		if token.Value == "require" {
			if i+1 < len(tokens) && tokens[i+1].Type == "LPAREN" {
				ctx.validateRequireCall(tokens, i)
			} else {
				ctx.errors = append(ctx.errors, fmt.Sprintf("require must be called as a function at line %d", token.Line))
			}
		}
		
		// Validar module.exports
		if token.Value == "module" && i+2 < len(tokens) && 
		   tokens[i+1].Type == "DOT" && tokens[i+2].Value == "exports" {
			ctx.validateModuleExports(tokens, i)
		}
		
		// Validar console usage
		if token.Value == "console" && i+2 < len(tokens) && tokens[i+1].Type == "DOT" {
			ctx.validateConsoleUsage(tokens, i)
		}
		
		// Validar process usage
		if token.Value == "process" && i+2 < len(tokens) && tokens[i+1].Type == "DOT" {
			ctx.validateProcessUsage(tokens, i)
		}
	}
}

// Validar llamada a require
func (ctx *SemanticContext) validateRequireCall(tokens []Token, reqIndex int) {
	// Buscar el argumento de require
	parenStart := reqIndex + 1
	if parenStart >= len(tokens) || tokens[parenStart].Type != "LPAREN" {
		return
	}
	
	// Buscar paréntesis de cierre
	parenEnd := -1
	parenCount := 1
	for i := parenStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LPAREN" {
			parenCount++
		} else if tokens[i].Type == "RPAREN" {
			parenCount--
			if parenCount == 0 {
				parenEnd = i
				break
			}
		}
	}
	
	if parenEnd == -1 {
		ctx.errors = append(ctx.errors, fmt.Sprintf("Missing closing parenthesis for require() at line %d", tokens[reqIndex].Line))
		return
	}
	
	// Verificar argumentos
	args := tokens[parenStart+1 : parenEnd]
	if len(args) == 0 {
		ctx.errors = append(ctx.errors, fmt.Sprintf("require() called without arguments at line %d", tokens[reqIndex].Line))
	} else if len(args) == 1 && args[0].Type == "STRING" {
		// Extraer el nombre del módulo
		moduleName := strings.Trim(args[0].Value, "\"'`")
		ctx.requireStatements = append(ctx.requireStatements, moduleName)
		
		// Validar nombres de módulos comunes
		ctx.validateModuleName(moduleName, tokens[reqIndex].Line)
	} else if len(args) > 1 {
		ctx.errors = append(ctx.errors, fmt.Sprintf("require() called with multiple arguments at line %d", tokens[reqIndex].Line))
	} else {
		ctx.errors = append(ctx.errors, fmt.Sprintf("require() argument must be a string at line %d", tokens[reqIndex].Line))
	}
}

// Validar nombres de módulos
func (ctx *SemanticContext) validateModuleName(moduleName string, line int) {
	// Verificar módulos core de Node.js
	coreModules := []string{
		"assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns", "domain",
		"events", "fs", "http", "https", "net", "os", "path", "punycode", "querystring",
		"readline", "stream", "string_decoder", "tls", "tty", "url", "util", "v8", "vm", "zlib",
	}
	
	isCore := false
	for _, core := range coreModules {
		if moduleName == core {
			isCore = true
			break
		}
	}
	
	// Validaciones específicas
	if strings.Contains(moduleName, " ") {
		ctx.errors = append(ctx.errors, fmt.Sprintf("Module name '%s' contains spaces at line %d", moduleName, line))
	}
	
	if strings.HasPrefix(moduleName, ".") && !strings.HasPrefix(moduleName, "./") && !strings.HasPrefix(moduleName, "../") {
		ctx.errors = append(ctx.errors, fmt.Sprintf("Invalid relative path '%s' at line %d", moduleName, line))
	}
	
	// Advertencia para módulos no estándar sin ./
	if !isCore && !strings.HasPrefix(moduleName, ".") && !strings.HasPrefix(moduleName, "/") {
		// Es probablemente un paquete npm, esto está bien
	}
}

// Validar module.exports
func (ctx *SemanticContext) validateModuleExports(tokens []Token, moduleIndex int) {
	// Verificar si hay asignación
	assignIndex := -1
	for i := moduleIndex + 3; i < len(tokens) && i < moduleIndex + 10; i++ {
		if tokens[i].Type == "ASSIGN" {
			assignIndex = i
			break
		}
		if tokens[i].Type == "SEMICOLON" || tokens[i].Type == "LBRACE" {
			break
		}
	}
	
	if assignIndex != -1 {
		// Hay asignación, registrar export
		ctx.exportedItems = append(ctx.exportedItems, fmt.Sprintf("module.exports at line %d", tokens[moduleIndex].Line))
	}
}

// Validar uso de console
func (ctx *SemanticContext) validateConsoleUsage(tokens []Token, consoleIndex int) {
	if consoleIndex + 2 >= len(tokens) {
		return
	}
	
	method := tokens[consoleIndex + 2].Value
	validMethods := []string{"log", "error", "warn", "info", "debug", "trace", "assert", "clear", "count", "time", "timeEnd", "group", "groupEnd", "table"}
	
	isValid := false
	for _, validMethod := range validMethods {
		if method == validMethod {
			isValid = true
			break
		}
	}
	
	if !isValid {
		ctx.errors = append(ctx.errors, fmt.Sprintf("Unknown console method '%s' at line %d", method, tokens[consoleIndex].Line))
	}
}

// Validar uso de process
func (ctx *SemanticContext) validateProcessUsage(tokens []Token, processIndex int) {
	if processIndex + 2 >= len(tokens) {
		return
	}
	
	property := tokens[processIndex + 2].Value
	validProperties := []string{"env", "argv", "stdout", "stderr", "stdin", "pid", "platform", "version", "cwd", "exit", "nextTick", "on", "emit"}
	
	isValid := false
	for _, validProp := range validProperties {
		if property == validProp {
			isValid = true
			break
		}
	}
	
	if !isValid {
		ctx.errors = append(ctx.errors, fmt.Sprintf("Unknown process property '%s' at line %d", property, tokens[processIndex].Line))
	}
}

// Validar statements require
func (ctx *SemanticContext) validateRequireStatements() {
	// Verificar duplicados
	seen := make(map[string]bool)
	for _, module := range ctx.requireStatements {
		if seen[module] {
			ctx.errors = append(ctx.errors, fmt.Sprintf("Duplicate require for module '%s'", module))
		}
		seen[module] = true
	}
}

// Validar exports
func (ctx *SemanticContext) validateExports() {
	if len(ctx.exportedItems) == 0 {
		// No hay exports, podría ser un script sin módulos
	} else if len(ctx.exportedItems) > 1 {
		ctx.errors = append(ctx.errors, fmt.Sprintf("Multiple exports found: %v", ctx.exportedItems))
	}
}

// Validar async/await
func (ctx *SemanticContext) validateAsyncAwait(tokens []Token) {
	awaitUsage := []int{}
	asyncFunctions := []int{}
	
	for i, token := range tokens {
		if token.Type == "KEYWORD" && token.Value == "async" {
			asyncFunctions = append(asyncFunctions, token.Line)
		} else if token.Type == "KEYWORD" && token.Value == "await" {
			awaitUsage = append(awaitUsage, token.Line)
			
			// Verificar si await está en función async
			if !ctx.isInAsyncContext(tokens, i) {
				ctx.errors = append(ctx.errors, fmt.Sprintf("await used outside async function at line %d", token.Line))
			}
		}
	}
}

// Verificar si await está en contexto async
func (ctx *SemanticContext) isInAsyncContext(tokens []Token, awaitIndex int) bool {
	// Buscar hacia atrás para encontrar function async
	functionDepth := 0
	for i := awaitIndex - 1; i >= 0; i-- {
		if tokens[i].Type == "RBRACE" {
			functionDepth++
		} else if tokens[i].Type == "LBRACE" {
			if functionDepth == 0 {
				// Buscar async antes de esta función
				for j := i - 1; j >= 0 && j >= i-10; j-- {
					if tokens[j].Type == "KEYWORD" && tokens[j].Value == "async" {
						return true
					}
					if tokens[j].Type == "KEYWORD" && tokens[j].Value == "function" {
						break
					}
				}
				return false
			}
			functionDepth--
		}
	}
	return false
}

// Validar arrow functions
func (ctx *SemanticContext) validateArrowFunctions(tokens []Token) {
	for i, token := range tokens {
		if token.Type == "ARROW" {
			// Verificar sintaxis de arrow function
			if i == 0 {
				ctx.errors = append(ctx.errors, fmt.Sprintf("Invalid arrow function syntax at line %d", token.Line))
				continue
			}
			
			// Verificar parámetros antes de =>
			paramStart := ctx.findArrowFunctionParams(tokens, i)
			if paramStart == -1 {
				ctx.errors = append(ctx.errors, fmt.Sprintf("Invalid arrow function parameters at line %d", token.Line))
			}
			
			// Verificar cuerpo después de =>
			if i+1 >= len(tokens) {
				ctx.errors = append(ctx.errors, fmt.Sprintf("Missing arrow function body at line %d", token.Line))
			}
		}
	}
}

// Encontrar parámetros de arrow function
func (ctx *SemanticContext) findArrowFunctionParams(tokens []Token, arrowIndex int) int {
	// Caso 1: (param1, param2) =>
	if arrowIndex > 0 && tokens[arrowIndex-1].Type == "RPAREN" {
		// Buscar LPAREN correspondiente
		parenCount := 1
		for i := arrowIndex - 2; i >= 0; i-- {
			if tokens[i].Type == "RPAREN" {
				parenCount++
			} else if tokens[i].Type == "LPAREN" {
				parenCount--
				if parenCount == 0 {
					return i
				}
			}
		}
	}
	
	// Caso 2: param =>
	if arrowIndex > 0 && tokens[arrowIndex-1].Type == "IDENTIFIER" {
		return arrowIndex - 1
	}
	
	return -1
}

// Validar destructuring
func (ctx *SemanticContext) validateDestructuring(tokens []Token) {
	for i, token := range tokens {
		if token.Type == "LBRACE" || token.Type == "LBRACKET" {
			if ctx.isDestructuringPattern(tokens, i) {
				ctx.validateDestructuringPattern(tokens, i)
			}
		}
	}
}

// Verificar si es patrón de destructuring
func (ctx *SemanticContext) isDestructuringPattern(tokens []Token, index int) bool {
	// Verificar contextos donde aparece destructuring
	if index == 0 {
		return false
	}
	
	prevToken := tokens[index-1]
	
	// Después de let/const/var
	if prevToken.Type == "KEYWORD" && (prevToken.Value == "let" || prevToken.Value == "const" || prevToken.Value == "var") {
		return true
	}
	
	// Después de =
	if prevToken.Type == "ASSIGN" {
		return true
	}
	
	// En parámetros de función
	if ctx.isInFunctionParameters(tokens, index) {
		return true
	}
	
	return false
}

// Verificar si está en parámetros de función
func (ctx *SemanticContext) isInFunctionParameters(tokens []Token, index int) bool {
	// Buscar hacia atrás para encontrar function(
	for i := index - 1; i >= 0; i-- {
		if tokens[i].Type == "LPAREN" {
			// Verificar si hay function antes
			for j := i - 1; j >= 0 && j >= i-5; j-- {
				if tokens[j].Type == "KEYWORD" && tokens[j].Value == "function" {
					return true
				}
				if tokens[j].Type != "IDENTIFIER" && tokens[j].Type != "KEYWORD" {
					break
				}
			}
		}
		if tokens[i].Type == "SEMICOLON" || tokens[i].Type == "LBRACE" {
			break
		}
	}
	return false
}

// Validar patrón de destructuring
func (ctx *SemanticContext) validateDestructuringPattern(tokens []Token, startIndex int) {
	openChar := tokens[startIndex].Type
	closeChar := "RBRACE"
	if openChar == "LBRACKET" {
		closeChar = "RBRACKET"
	}
	
	// Encontrar cierre
	endIndex := -1
	bracketCount := 1
	for i := startIndex + 1; i < len(tokens); i++ {
		if tokens[i].Type == openChar {
			bracketCount++
		} else if tokens[i].Type == closeChar {
			bracketCount--
			if bracketCount == 0 {
				endIndex = i
				break
			}
		}
	}
	
	if endIndex == -1 {
		ctx.errors = append(ctx.errors, fmt.Sprintf("Unclosed destructuring pattern at line %d", tokens[startIndex].Line))
		return
	}
	
	// Validar contenido del destructuring
	content := tokens[startIndex+1 : endIndex]
	if len(content) == 0 {
		ctx.errors = append(ctx.errors, fmt.Sprintf("Empty destructuring pattern at line %d", tokens[startIndex].Line))
	}
	
	// Verificar sintaxis válida
	ctx.validateDestructuringContent(content, tokens[startIndex].Line, openChar == "LBRACE")
}

// Validar contenido de destructuring
func (ctx *SemanticContext) validateDestructuringContent(tokens []Token, line int, isObject bool) {
	if len(tokens) == 0 {
		return
	}
	
	// Para object destructuring, verificar que hay identificadores válidos
	if isObject {
		for i, token := range tokens {
			if token.Type == "IDENTIFIER" {
				// Verificar que no sea una keyword
				if isKeyword(token.Value) {
					ctx.errors = append(ctx.errors, fmt.Sprintf("Cannot use keyword '%s' as destructuring variable at line %d", token.Value, line))
				}
			} else if token.Type == "COLON" {
				// Property renaming: {prop: newName}
				if i == 0 || i == len(tokens)-1 {
					ctx.errors = append(ctx.errors, fmt.Sprintf("Invalid property renaming in destructuring at line %d", line))
				}
			}
		}
	}
	
	// Para array destructuring, verificar elementos válidos
	if !isObject {
		for _, token := range tokens {
			if token.Type == "IDENTIFIER" && isKeyword(token.Value) {
				ctx.errors = append(ctx.errors, fmt.Sprintf("Cannot use keyword '%s' as destructuring variable at line %d", token.Value, line))
			}
		}
	}
}

// Funciones auxiliares existentes mejoradas
func isKeyword(value string) bool {
	keywords := []string{
		"const", "let", "var", "function", "if", "else", "for", "while", "do",
		"return", "true", "false", "null", "undefined", "class", "extends",
		"import", "export", "default", "from", "try", "catch", "finally",
		"throw", "new", "this", "super", "typeof", "instanceof", "in", "of",
		"delete", "void", "break", "continue", "switch", "case", "async", "await",
	}
	for _, keyword := range keywords {
		if value == keyword {
			return true
		}
	}
	return false
}

func isBuiltIn(value string) bool {
	builtins := []string{
		"console", "require", "module", "exports", "process", "global", 
		"__dirname", "__filename", "Buffer", "setTimeout", "setInterval",
		"clearTimeout", "clearInterval", "setImmediate", "clearImmediate",
		"Promise", "Array", "Object", "String", "Number", "Boolean", "Date",
		"RegExp", "Error", "TypeError", "ReferenceError", "SyntaxError",
		"JSON", "Math", "parseInt", "parseFloat", "isNaN", "isFinite",
		"encodeURI", "decodeURI", "encodeURIComponent", "decodeURIComponent",
	}
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
	
	// Validación de entrada
	if strings.TrimSpace(req.Code) == "" {
		http.Error(w, "Empty code provided", http.StatusBadRequest)
		return
	}
	
	// Análisis Léxico
	lexer := NewLexer(req.Code)
	tokens := lexer.Tokenize()
	
	// Análisis Sintáctico
	ast, syntaxErrors := parseToAST(tokens)
	
	// Análisis Semántico
	semanticErrors := performSemanticAnalysis(tokens)
	
	// Validaciones adicionales específicas de Node.js
	nodeValidationErrors := validateNodeJSSpecific(tokens)
	semanticErrors = append(semanticErrors, nodeValidationErrors...)
	
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

// Validaciones específicas adicionales de Node.js
func validateNodeJSSpecific(tokens []Token) []string {
	var errors []string
	
	// Validar uso de global variables de Node.js
	for i, token := range tokens {
		if token.Type == "IDENTIFIER" {
			switch token.Value {
			case "__dirname", "__filename":
				// Verificar que se use correctamente
				if i+1 < len(tokens) && tokens[i+1].Type == "ASSIGN" {
					errors = append(errors, fmt.Sprintf("Cannot assign to Node.js global variable '%s' at line %d", token.Value, token.Line))
				}
			case "Buffer":
				// Verificar uso de Buffer
				if i+1 < len(tokens) && tokens[i+1].Type == "DOT" {
					if i+2 < len(tokens) {
						method := tokens[i+2].Value
						validBufferMethods := []string{"from", "alloc", "allocUnsafe", "isBuffer", "byteLength", "compare", "concat"}
						isValid := false
						for _, validMethod := range validBufferMethods {
							if method == validMethod {
								isValid = true
								break
							}
						}
						if !isValid {
							errors = append(errors, fmt.Sprintf("Unknown Buffer method '%s' at line %d", method, token.Line))
						}
					}
				}
			}
		}
	}
	
	// Validar patrones de callback y promesas
	errors = append(errors, validateCallbackPatterns(tokens)...)
	errors = append(errors, validatePromisePatterns(tokens)...)
	
	return errors
}

// Validar patrones de callback
func validateCallbackPatterns(tokens []Token) []string {
	var errors []string
	
	for i, token := range tokens {
		// Buscar patrones como function(err, data)
		if token.Type == "KEYWORD" && token.Value == "function" {
			// Buscar parámetros
			parenStart := -1
			for j := i + 1; j < len(tokens) && j < i + 5; j++ {
				if tokens[j].Type == "LPAREN" {
					parenStart = j
					break
				}
			}
			
			if parenStart != -1 {
				// Encontrar paréntesis de cierre
				parenEnd := -1
				parenCount := 1
				for j := parenStart + 1; j < len(tokens); j++ {
					if tokens[j].Type == "LPAREN" {
						parenCount++
					} else if tokens[j].Type == "RPAREN" {
						parenCount--
						if parenCount == 0 {
							parenEnd = j
							break
						}
					}
				}
				
				if parenEnd != -1 {
					params := tokens[parenStart+1 : parenEnd]
					if len(params) >= 3 && params[0].Type == "IDENTIFIER" && params[0].Value == "err" {
						// Patrón de callback encontrado, validar uso
						if !validateCallbackErrorHandling(tokens, i, parenEnd) {
							errors = append(errors, fmt.Sprintf("Callback function with 'err' parameter should handle errors at line %d", token.Line))
						}
					}
				}
			}
		}
	}
	
	return errors
}

// Validar manejo de errores en callbacks
func validateCallbackErrorHandling(tokens []Token, funcStart, parenEnd int) bool {
	// Buscar el cuerpo de la función
	braceStart := -1
	for i := parenEnd + 1; i < len(tokens) && i < parenEnd + 5; i++ {
		if tokens[i].Type == "LBRACE" {
			braceStart = i
			break
		}
	}
	
	if braceStart == -1 {
		return false
	}
	
	// Buscar el final del cuerpo de la función
	braceEnd := -1
	braceCount := 1
	for i := braceStart + 1; i < len(tokens); i++ {
		if tokens[i].Type == "LBRACE" {
			braceCount++
		} else if tokens[i].Type == "RBRACE" {
			braceCount--
			if braceCount == 0 {
				braceEnd = i
				break
			}
		}
	}
	
	if braceEnd == -1 {
		return false
	}
	
	// Buscar if (err) o similar en el cuerpo
	funcBody := tokens[braceStart+1 : braceEnd]
	for i, token := range funcBody {
		if token.Type == "KEYWORD" && token.Value == "if" {
			// Buscar si verifica err
			if i+1 < len(funcBody) && funcBody[i+1].Type == "LPAREN" {
				if i+2 < len(funcBody) && funcBody[i+2].Type == "IDENTIFIER" && funcBody[i+2].Value == "err" {
					return true
				}
			}
		}
	}
	
	return false
}

// Validar patrones de promesas
func validatePromisePatterns(tokens []Token) []string {
	var errors []string
	
	for i, token := range tokens {
		// Buscar new Promise
		if token.Type == "KEYWORD" && token.Value == "new" {
			if i+1 < len(tokens) && tokens[i+1].Type == "IDENTIFIER" && tokens[i+1].Value == "Promise" {
				errors = append(errors, validatePromiseConstructor(tokens, i)...)
			}
		}
		
		// Buscar .then(), .catch(), .finally()
		if token.Type == "DOT" && i+1 < len(tokens) && tokens[i+1].Type == "IDENTIFIER" {
			method := tokens[i+1].Value
			if method == "then" || method == "catch" || method == "finally" {
				errors = append(errors, validatePromiseMethod(tokens, i, method)...)
			}
		}
	}
	
	return errors
}

// Validar constructor de Promise
func validatePromiseConstructor(tokens []Token, newIndex int) []string {
	var errors []string
	
	// Buscar paréntesis después de Promise
	parenStart := -1
	for i := newIndex + 2; i < len(tokens) && i < newIndex + 5; i++ {
		if tokens[i].Type == "LPAREN" {
			parenStart = i
			break
		}
	}
	
	if parenStart == -1 {
		errors = append(errors, fmt.Sprintf("Promise constructor missing parentheses at line %d", tokens[newIndex].Line))
		return errors
	}
	
	// Verificar que tiene una función como argumento
	if parenStart+1 < len(tokens) {
		if tokens[parenStart+1].Type == "KEYWORD" && tokens[parenStart+1].Value == "function" {
			// OK
		} else if tokens[parenStart+1].Type == "LPAREN" {
			// Arrow function
		} else {
			errors = append(errors, fmt.Sprintf("Promise constructor requires a function argument at line %d", tokens[newIndex].Line))
		}
	}
	
	return errors
}

// Validar métodos de Promise
func validatePromiseMethod(tokens []Token, dotIndex int, method string) []string {
	var errors []string
	
	// Verificar que tiene paréntesis después del método
	if dotIndex+2 < len(tokens) && tokens[dotIndex+2].Type != "LPAREN" {
		errors = append(errors, fmt.Sprintf("Promise.%s() missing parentheses at line %d", method, tokens[dotIndex].Line))
	}
	
	return errors
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": "2.0",
		"features": "Enhanced semantic analysis with Node.js validation",
	})
}

func main() {
	http.HandleFunc("/analyze", analyzeHandler)
	http.HandleFunc("/health", healthHandler)
	
	fmt.Println("🚀 Servidor Node.js Analyzer iniciado en puerto 8080")
	fmt.Println("📋 Características mejoradas:")
	fmt.Println("   ✅ Detección de declaraciones duplicadas de variables")
	fmt.Println("   ✅ Validación de condiciones booleanas en while/if")
	fmt.Println("   ✅ Validaciones semánticas completas de Node.js")
	fmt.Println("   ✅ Análisis de async/await, arrow functions, destructuring")
	fmt.Println("   ✅ Validación de patrones de callback y promesas")
	fmt.Println("   ✅ Verificación de módulos require() y exports")
	fmt.Println()
	fmt.Println("🔧 Endpoints disponibles:")
	fmt.Println("   POST /analyze - Analizar código Node.js")
	fmt.Println("   GET  /health  - Estado del servidor")
	
	log.Fatal(http.ListenAndServe(":8080", nil))
}