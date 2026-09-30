# AnonDSL: Linguagem Específica de Domínio para Políticas de Anonimização de Dados

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![PLY](https://img.shields.io/badge/Lex%20%26%20Yacc-PLY-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

O **AnonDSL** é uma Linguagem de Domínio Específico (DSL) declarativa projetada para simplificar e padronizar a criação de políticas de anonimização de dados pessoais sensíveis (PII). Desenvolvida no âmbito da disciplina de **Teoria da Computação e Compiladores**, a ferramenta permite separar as regras de privacidade do código da aplicação, garantindo conformidade com legislações como a LGPD e o GDPR.

---

## 📌 Funcionalidades Principais

* **Declaração Declarativa:** Especificação intuitiva de entidades, níveis de risco e ações de anonimização.
* **Mapeamento de Entidades Sensíveis:** Reconhecimento automático de padrões em texto livre (CPF, E-mail, Telefone, CEP e Datas).
* **Ações Flexíveis de Transformação:**
  * `suppress`: Ocultação total da informação.
  * `generalize`: Mascaramento parcial ou perda controlada de precisão.
  * `keep`: Manutenção do valor original.
* **Análise Sintática e Semântica Integrada:** Validação da estrutura gramatical e verificação de regras de negócio antes da aplicação da política.

---

## 🚀 Sintaxe da Linguagem (AnonDSL)

Uma política em AnonDSL é composta pelo bloco `policy`, contendo as entidades (`entity`) com os respetivos atributos de risco (`risk`) e ação de transformação (`action`).

```text
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
}