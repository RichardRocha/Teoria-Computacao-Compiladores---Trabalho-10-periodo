import os
import sys
import ply.lex as lex
import ply.yacc as yacc

class PIILexer:
    tokens = ('CPF', 'EMAIL', 'TELEFONE', 'CEP', 'DATA', 'PALAVRA', 'PONTUACAO')

    t_CPF = r'\b\d{3}\.\d{3}\.\d{3}\-\d{2}\b|\b\d{11}\b'
    t_EMAIL = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    t_TELEFONE = r'\(?\d{2}\)?\s?\d{4,5}\-\d{4}'
    t_CEP = r'\b\d{5}\-\d{3}\b'
    t_DATA = r'\b\d{2}\/\d{2}\/\d{4}\b'
    t_PONTUACAO = r'[.,!?;:()"]'
    t_PALAVRA = r'[^\s.,!?;:()"]+'

    t_ignore = ' \t\r\n'

    def t_error(self, t):
        t.lexer.skip(1)

    def __init__(self):
        self.lexer = lex.lex(module=self)

class PolicyCompiler:
    tokens = (
        'POLICY', 'ENTITY', 'RISK', 'ACTION',
        'RISK_LEVEL', 'ACTION_TYPE', 'IDENTIFIER',
        'LBRACE', 'RBRACE', 'COLON', 'SEMICOLON'
    )

    reserved = {
        'policy': 'POLICY',
        'entity': 'ENTITY',
        'risk': 'RISK',
        'action': 'ACTION'
    }

    t_LBRACE = r'\{'
    t_RBRACE = r'\}'
    t_COLON = r':'
    t_SEMICOLON = r';'

    def t_RISK_LEVEL(self, t):
        r'critical|high|medium|low'
        return t

    def t_ACTION_TYPE(self, t):
        r'suppress|generalize|keep'
        return t

    def t_IDENTIFIER(self, t):
        r'[a-zA-Z_][a-zA-Z0-9_]*'
        t.type = self.reserved.get(t.value, 'IDENTIFIER')
        return t

    def p_policy_root(self, p):
        'policy_spec : POLICY IDENTIFIER LBRACE entity_list RBRACE'
        p[0] = {'policy_name': p[2], 'entities': p[4]}

    def p_entity_list(self, p):
        '''entity_list : entity_decl
                       | entity_decl entity_list'''
        if len(p) == 2:
            p[0] = [p[1]]
        else:
            p[0] = [p[1]] + p[2]

    def p_entity_decl(self, p):
        'entity_decl : ENTITY IDENTIFIER LBRACE property_list RBRACE'
        p[0] = {'entity': p[2], 'props': p[4]}

    def p_property_list(self, p):
        '''property_list : property
                         | property property_list'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = {**p[1], **p[2]}

    def p_property_risk(self, p):
        'property : RISK COLON RISK_LEVEL SEMICOLON'
        p[0] = {'risk': p[3]}

    def p_property_action(self, p):
        'property : ACTION COLON ACTION_TYPE SEMICOLON'
        p[0] = {'action': p[3]}

    def p_error(self, p):
        if p:
            raise SyntaxError(f"Erro sintático no token '{p.value}' (linha {p.lineno})")
        else:
            raise SyntaxError("Erro sintático: Fim de arquivo inesperado")

    def __init__(self):
        self.lexer = lex.lex(module=self)
        self.parser = yacc.yacc(module=self, write_tables=False, debug=False)

    def parse(self, code):
        ast = self.parser.parse(code, lexer=self.lexer)
        self.validate_semantics(ast)
        return ast

    def validate_semantics(self, ast):
        valid_entities = {'CPF', 'EMAIL', 'TELEFONE', 'CEP', 'DATA'}
        valid_risks = {'critical', 'high', 'medium', 'low'}
        valid_actions = {'suppress', 'generalize', 'keep'}

        seen_entities = set()
        for ent in ast['entities']:
            name = ent['entity']
            props = ent['props']

            if name in seen_entities:
                raise ValueError(f"Erro Semântico: Entidade '{name}' declarada mais de uma vez.")
            seen_entities.add(name)

            if name not in valid_entities:
                raise ValueError(f"Erro Semântico: Entidade '{name}' desconhecida. Permitidas: {valid_entities}")

            if 'risk' not in props or 'action' not in props:
                raise ValueError(f"Erro Semântico: Propriedades 'risk' e 'action' são obrigatórias em '{name}'.")

            if props['risk'] not in valid_risks:
                raise ValueError(f"Erro Semântico: Risco '{props['risk']}' inválido em '{name}'.")

            if props['action'] not in valid_actions:
                raise ValueError(f"Erro Semântico: Ação '{props['action']}' inválida em '{name}'.")

setattr(PolicyCompiler, 't_ignore', ' \t\r\n')
setattr(PolicyCompiler, 't_error', lambda self, t: t.lexer.skip(1))

class AnonymizerEngine:
    def __init__(self):
        self.pii_lexer = PIILexer()

    def transform_value(self, token_type, value, action):
        if action == 'suppress':
            return f"[{token_type}_SUPPRESSED]"
        
        elif action == 'generalize':
            if token_type == 'CPF':
                return value[:3] + '.***.***-**'
            elif token_type == 'EMAIL':
                parts = value.split('@')
                return parts[0][0] + '***@' + parts[1]
            elif token_type == 'TELEFONE':
                return value[:4] + ' *****-****'
            elif token_type == 'CEP':
                return value[:5] + '-***'
            elif token_type == 'DATA':
                parts = value.split('/')
                return f"**/**/{parts[2]}" if len(parts) == 3 else "**/**/****"
            return "[DADO GENERALIZADO]"

        return value  # 'keep'

    def anonymize_text(self, text, ast):
        rules = {e['entity']: e['props']['action'] for e in ast['entities']}

        self.pii_lexer.lexer.input(text)
        result = []
        last_pos = 0

        for tok in self.pii_lexer.lexer:
            result.append(text[last_pos:tok.lexpos])

            if tok.type in rules:
                action = rules[tok.type]
                transformed = self.transform_value(tok.type, tok.value, action)
                result.append(transformed)
            else:
                result.append(tok.value)

            last_pos = tok.lexpos + len(tok.value)

        result.append(text[last_pos:])
        return "".join(result)


if __name__ == '__main__':
    policy_code = """
    policy LGPD_Protecao {
        entity CPF {
            risk: critical;
            action: suppress;
        }
        entity EMAIL {
            risk: high;
            action: generalize;
        }
        entity TELEFONE {
            risk: low;
            action: keep;
        }
        entity CEP {
            risk: medium;
            action: generalize;
        }
        entity DATA {
            risk: medium;
            action: generalize;
        }
    }
    """

    caminho_arquivo = 'teste.txt'

    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            sample_text = f.read()
    except FileNotFoundError:
        print(f"Erro: O arquivo '{caminho_arquivo}' não foi encontrado no diretório atual.")
        sys.exit(1)

    compiler = PolicyCompiler()
    ast = compiler.parse(policy_code)

    print("--- AST GERADA DA POLÍTICA ---")
    print(ast)

    engine = AnonymizerEngine()
    anonymized_text = engine.anonymize_text(sample_text, ast)

    print(f"\n--- CONTEÚDO ORIGINAL DE '{caminho_arquivo}' ---")
    print(sample_text)

    print("\n--- TEXTO ANONIMIZADO ---")
    print(anonymized_text)