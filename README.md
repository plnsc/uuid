# UUID (Universally Unique Identifier)

## O que é

**UUID** é um identificador de **128 bits** que distingue informações de forma única em sistemas de computação, sem autoridade central que coordene sua geração.

- **Representação**: 32 caracteres hexadecimais em 5 grupos separados por hífens:
  ```
  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  ```
  Exemplo: `550e8400-e29b-41d4-a716-446655440000`
- **Unicidade**: a probabilidade de colisão é tão baixa que, na prática, UUIDs aleatórios são considerados únicos globalmente.

### Usos comuns
- Identificar registros em bancos de dados (alternativa a IDs sequenciais)
- Identificar sessões, transações ou requisições em sistemas distribuídos
- Nomear arquivos ou recursos de forma única
- Evitar conflitos ao combinar dados de múltiplas fontes (não depende de contador central)

---

## Especificação: RFC 9562

A **RFC 9562** ("Universally Unique IDentifiers (UUIDs)"), publicada pela IETF em **abril de 2024**, **obsoleta a RFC 4122**. Seu Apêndice A traz vetores de teste com exemplos reais para cada versão.

### Fontes oficiais
| Formato | Link |
|---|---|
| HTML | https://www.rfc-editor.org/rfc/rfc9562.html |
| Texto puro | https://www.rfc-editor.org/rfc/rfc9562.txt |
| PDF | https://www.rfc-editor.org/rfc/rfc9562.pdf |
| IETF Datatracker (histórico/status) | https://datatracker.ietf.org/doc/html/rfc9562 |

---

## Versões definidas

| Versão | Nome | Descrição |
|---|---|---|
| **v1** | Gregorian Time | Timestamp + endereço MAC (node) + sequência de clock |
| **v2** | DCE Security | Como a v1, mas parte do campo vira domínio local (UID/GID). Raramente implementada |
| **v3** | Name-based (MD5) | Hash MD5 de um namespace + nome. Determinística |
| **v4** | Random | Números aleatórios/pseudoaleatórios. A mais usada atualmente |
| **v5** | Name-based (SHA-1) | Igual à v3, mas com SHA-1 (mais segura contra colisões) |
| **v6** | Reordered Gregorian Time | Reordena os bits de timestamp da v1 para gerar UUIDs monotonicamente crescentes |
| **v7** | Unix Epoch Time | Timestamp Unix em milissegundos + bytes aleatórios; ordenável, ideal para chaves de banco |
| **v8** | Custom | Mantém o formato do UUID, mas deixa o conteúdo livre para usos específicos |

### Valores especiais
- **Nil UUID**: todos os bits zerados (`00000000-0000-0000-0000-000000000000`)
- **Max UUID**: todos os bits em 1 (novidade da RFC 9562)

---

## Estrutura de bits comparada

Todo UUID tem 128 bits, com **4 bits de versão** e **2 bits de variante** (a variante da RFC 9562 usa os bits `10`).

| Versão | Composição dos 128 bits |
|---|---|
| **v1** | `time_low`(32) + `time_mid`(16) + `version`(4) + `time_hi`(12) + `variant`(2) + `clock_seq`(14) + `node/MAC`(48) |
| **v6** | Mesmos campos da v1, com o timestamp reordenado do mais para o menos significativo (`time_hi` → `time_mid` → `time_low`) |
| **v7** | `unix_ts_ms`(48) + `version`(4) + `rand_a`(12) + `variant`(2) + `rand_b`(62) |
| **v4** | Mesmo esqueleto da v7, com todos os campos de dados aleatórios: `random`(48) + `version`(4) + `random`(12) + `variant`(2) + `random`(62) |

**Observação-chave**: v1 e v6 têm os mesmos campos (muda só a ordem do timestamp); v7 e v4 têm o mesmo esqueleto de bits (muda só se o conteúdo é timestamp ou aleatório).

> No código, essa tabela corresponde a `assemble` (campos → UUID) e `decode` (o inverso). O diagrama de bits completo está no cabeçalho de cada implementação.

---

## Como a v7 gera monotonicidade

O timestamp Unix em milissegundos ocupa os **48 bits mais significativos** do UUIDv7, os primeiros a serem comparados numa ordenação byte a byte (ou lexicográfica em hexadecimal).

Logo, **ordenar pelo valor bruto já resulta na ordem cronológica de criação**, sem lógica adicional. Os bits aleatórios (`rand_a` e `rand_b`) só desempatam UUIDs do mesmo milissegundo: não alteram a ordem geral, apenas evitam que dois UUIDs do mesmo instante sejam idênticos.

Isso torna a v7 adequada como chave primária, por favorecer índices B-tree, evitando a fragmentação que inserções em posições aleatórias causam na v4.

> As implementações deste repositório vão além da RFC e garantem ordenação **estrita** mesmo dentro do mesmo milissegundo, usando `rand_a` como contador em vez de bits aleatórios (Método 2, RFC 9562 §6.2). Veja `Generator` e `next_state`.

---

## Exemplo prático: um UUIDv7 real, campo a campo

UUID gerado em **13/09/2026 às 02:26:10.253 UTC**:

```
01a09896-1ecd-7b03-bb26-376dea2187a4
```

| Campo | Valor hex | Bits | Significado |
|---|---|---|---|
| `unix_ts_ms` | `01a098961ecd` | 48 | Timestamp Unix em milissegundos → 13/09/2026 02:26:10.253 UTC |
| `version` | `7` | 4 | Sempre `7`; é esse nibble, logo após o segundo hífen, que identifica a versão, a forma mais rápida de reconhecê-la só olhando a string |
| `rand_a` | `b03` | 12 | Bits aleatórios (sem significado especial) |
| `variant` | `10xx` (primeiro nibble `b` = `1011`) | 2 | Os 2 bits mais significativos do nibble indicam a variante RFC 9562 (`10`); por isso o primeiro caractere desse grupo fica sempre entre `8` e `b` |
| `rand_b` | `b26376dea2187a4` | 62 | Bits aleatórios; reduzem a chance de colisão entre UUIDs do mesmo milissegundo |

> `decode` reproduz esta tabela para qualquer UUIDv7:
>
> ```bash
> ruby    -r./uuid_v7 -e 'p UUIDv7.decode("01a09896-1ecd-7b03-bb26-376dea2187a4")'
> python3 -c 'import uuid_v7; print(uuid_v7.decode("01a09896-1ecd-7b03-bb26-376dea2187a4"))'
> ```

---

## Implementações neste repositório

Quatro implementações da **v7**, cada uma usando apenas a biblioteca padrão da sua linguagem:

| Arquivo | Runtime | Como executar |
|---|---|---|
| [`uuid_v7.rb`](uuid_v7.rb) | Ruby | `ruby uuid_v7.rb` |
| [`uuid_v7.py`](uuid_v7.py) | Python 3 | `python3 uuid_v7.py` |
| [`uuid_v7.lua`](uuid_v7.lua) | Lua 5.3+ | `lua uuid_v7.lua` |
| [`uuid_v7.js`](uuid_v7.js) | Node 19+ | `node uuid_v7.js` |

Ruby é o original; Python, Lua e JavaScript são ports fiéis, com o mesmo layout de campos, a mesma monotonicidade e a mesma saída. São **compatíveis entre si**: um UUID gerado por qualquer uma decodifica de forma idêntica nas outras três.

### API comum

A mesma superfície nas quatro, mudando só a grafia (JavaScript usa camelCase, por ser o idioma da linguagem):

| Função | O que faz |
|---|---|
| `generate` | Um UUIDv7 monotônico (Método 2, RFC 9562 §6.2) |
| `generate_random` / `generateRandom` | Um UUIDv7 com `rand_a` e `rand_b` aleatórios (Método 1), que **não** garante ordenação dentro do mesmo milissegundo |
| `generate_bulk(n)` / `generateBulk(n)` | `n` UUIDs monotonicamente ordenados |
| `decode` | Decompõe um UUIDv7 nos seus campos |
| `valid?` / `is_valid` / `isValid` | `true` se for um UUIDv7 bem formado |

```ruby
require_relative 'uuid_v7'
UUIDv7.generate         # => "01a098b0-4420-71d4-83d6-582c6561f8d2"
```

```python
import uuid_v7
uuid_v7.generate()      # => "01a098b0-4477-70b4-9519-f2950ba49ead"
```

```lua
local uuid_v7 = require("uuid_v7")
uuid_v7.generate()      -- => "01a098b0-4138-7405-8dfc-89b4e3c48aa9"
```

```javascript
const uuid_v7 = require("./uuid_v7");
uuid_v7.generate();     // => "01a098db-9f10-7516-b387-53dd678b03ea"
```

### Testes

Não há framework: cada arquivo traz uma demonstração autocontida no final, executada ao rodá-lo diretamente. Ela verifica geração, decodificação, ordenação de 100 000 UUIDs, acesso concorrente e o vetor do Apêndice A.6 da RFC.

> Os resultados saem como `true`/`false` e `✓`/`✗`: o processo **não** retorna código de erro em caso de falha, então é preciso ler a saída.

### Particularidades do JavaScript

JavaScript não tem tipo inteiro, seus números são exatos só até 2^53 e roda num único event loop. As três consequências estão documentadas no cabeçalho de [`uuid_v7.js`](uuid_v7.js):

- a montagem usa `BigInt`, e por isso `decode` devolve `rand_b` (62 bits) como `BigInt`; `unix_ts_ms` (48) e `rand_a` (12) cabem num `Number` e continuam assim;
- não há mutex, porque só existe um event loop (worker threads recebem isolate e gerador próprios);
- `generateBulk(3.0)` é aceito, já que `3.0` e `3` são o mesmo valor.

A entropia vem de `crypto.getRandomValues`, sem fallback: ou há CSPRNG, ou o código falha, nunca degradando silenciosamente para `Math.random`.

### Particularidades do Lua

Lua não tem inteiros de 128 bits, relógio de milissegundos na biblioteca padrão, nem threads preemptivas. As três limitações estão contornadas e documentadas no cabeçalho de [`uuid_v7.lua`](uuid_v7.lua):

- o UUID é montado grupo hexadecimal por grupo hexadecimal, em vez de um único inteiro de 128 bits;
- o relógio usa `luaposix`/`luasocket` se instalados; caso contrário, interpola dentro do segundo (a ordenação nunca depende disso, só a precisão do timestamp);
- não há mutex, porque não há concorrência preemptiva a proteger.

A entropia vem de `/dev/urandom`; `math.random` entra só se ele não puder ser aberto e **não é criptograficamente seguro**. Os campos `entropy_source` e `clock_source` informam qual caminho está ativo.

---

## Referências
- RFC 9562: https://www.rfc-editor.org/rfc/rfc9562.html
- RFC 4122 (obsoletada pela RFC 9562): https://www.rfc-editor.org/rfc/rfc4122
- Cópia local para consulta offline: [`specs/rfc9562.txt`](specs/rfc9562.txt) (também em `.pdf` e `.mhtml`)
