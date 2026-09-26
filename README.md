# UUID (Universally Unique Identifier)

## O que é

Um identificador de **128 bits** que distingue informações de forma única, sem autoridade central coordenando a geração. Escreve-se como 32 caracteres hexadecimais em 5 grupos:

```
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
550e8400-e29b-41d4-a716-446655440000
```

A probabilidade de colisão é baixa o bastante para, na prática, tratá-los como únicos globalmente. Daí os usos típicos: chave de registro em banco (alternativa a IDs sequenciais), identificação de sessões, transações e requisições em sistemas distribuídos, nomes únicos de arquivos e junção de dados de várias fontes sem contador compartilhado.

---

## Especificação: RFC 9562

Publicada pela IETF em **abril de 2024**, a RFC 9562 ("Universally Unique IDentifiers (UUIDs)") **torna obsoleta a RFC 4122**. Seu Apêndice A traz vetores de teste para cada versão.

| Formato | Link |
|---|---|
| HTML | https://www.rfc-editor.org/rfc/rfc9562.html |
| Texto puro | https://www.rfc-editor.org/rfc/rfc9562.txt |
| PDF | https://www.rfc-editor.org/rfc/rfc9562.pdf |
| Datatracker (histórico/status) | https://datatracker.ietf.org/doc/html/rfc9562 |

### Versões definidas

| Versão | Nome | Descrição |
|---|---|---|
| **v1** | Gregorian Time | Timestamp + endereço MAC (node) + sequência de clock |
| **v2** | DCE Security | Como a v1, mas parte do campo vira domínio local (UID/GID). Raramente implementada |
| **v3** | Name-based (MD5) | Hash MD5 de namespace + nome. Determinística |
| **v4** | Random | Bits aleatórios/pseudoaleatórios. A mais usada hoje |
| **v5** | Name-based (SHA-1) | Igual à v3, com SHA-1 (mais resistente a colisões) |
| **v6** | Reordered Gregorian Time | Timestamp da v1 reordenado, o que torna os UUIDs crescentes |
| **v7** | Unix Epoch Time | Timestamp Unix em ms + bits aleatórios; ordenável, ideal para chave de banco |
| **v8** | Custom | Mantém o formato, deixa o conteúdo livre |

Dois valores especiais: **Nil UUID** (todos os bits em 0) e **Max UUID** (todos em 1, novidade da RFC 9562).

---

## Estrutura de bits comparada

Todo UUID tem 128 bits, dos quais **4 de versão** e **2 de variante** (na RFC 9562, a variante é `10`).

| Versão | Composição dos 128 bits |
|---|---|
| **v1** | `time_low`(32) + `time_mid`(16) + `version`(4) + `time_hi`(12) + `variant`(2) + `clock_seq`(14) + `node/MAC`(48) |
| **v6** | Mesmos campos da v1, timestamp reordenado do mais para o menos significativo (`time_hi` → `time_mid` → `time_low`) |
| **v7** | `unix_ts_ms`(48) + `version`(4) + `rand_a`(12) + `variant`(2) + `rand_b`(62) |
| **v4** | Mesmo esqueleto da v7, só com dados aleatórios: `random`(48) + `version`(4) + `random`(12) + `variant`(2) + `random`(62) |

Ou seja: v1 e v6 têm os mesmos campos (muda a ordem do timestamp), v7 e v4 têm o mesmo esqueleto (muda se o conteúdo é tempo ou aleatoriedade).

> No código, esta tabela é `assemble` (campos → UUID) e `decode` (o inverso). O diagrama completo está no cabeçalho de cada implementação.

---

## Como a v7 gera monotonicidade

O timestamp em milissegundos ocupa os **48 bits mais significativos**, os primeiros comparados numa ordenação byte a byte (ou lexicográfica em hexadecimal). Logo, **ordenar pelo valor bruto já dá a ordem cronológica de criação**, sem lógica extra. `rand_a` e `rand_b` só desempatam UUIDs do mesmo milissegundo.

Isso faz da v7 uma boa chave primária: as inserções chegam no fim do índice B-tree, evitando a fragmentação causada pelas posições aleatórias da v4.

> As implementações deste repositório vão além da RFC e garantem ordenação **estrita** mesmo dentro do mesmo milissegundo, usando `rand_a` como contador (Método 2, RFC 9562 §6.2). Veja `Generator` e `next_state`.

---

## Segurança e imprevisibilidade

UUID identifica, não autoriza. A RFC é explícita (§8, Security Considerations):

> Implementations SHOULD NOT assume that UUIDs are hard to guess. For example, they MUST NOT be used as security capabilities (identifiers whose mere possession grants access).

Link de reset de senha e ID de sessão pedem um token dedicado; se o identificador precisa participar de uma operação de segurança, a RFC recomenda a v4.

Na v7 isso é visível, porque quase nada nela é secreto: `unix_ts_ms` é o relógio de parede, `version` e `variant` são constantes, `rand_a` é um contador sequencial (Método 2). Toda a imprevisibilidade está nos 62 bits de `rand_b`.

Daí a RFC recomendar (SHOULD, §6.9) um **CSPRNG**, gerador em que prever a próxima saída é computacionalmente inviável mesmo para quem observou as anteriores. Um gerador comum pode ser estatisticamente impecável e ainda ter estado interno recuperável a partir de poucas saídas; recuperado o estado, toda a sequência passada e futura fica determinada. As seis implementações usam CSPRNG, e o único caminho degradado é o do Lua, descrito adiante.

### Pool de entropia

As seis sacam bits de um pool reabastecido em blocos de 4096 bytes, em vez de chamar o CSPRNG por UUID. O motivo é medido: um saque por chamada custa de ~570 ns (Lua) a ~3230 ns (Python, cujo `secrets.randbelow` faz amostragem com rejeição), contra 23 a 640 ns com pool. No `generate` completo, o ganho é de 4,8x no JavaScript, 2,4x no Rust, 1,5x no Python, 1,2x no Ruby, 1,14x no Lua e 1,13x no C. As três mais lentas ganham menos porque nelas o gargalo é a montagem da string.

Mascarar bits é válido porque todo chamador pede uma faixa potência de dois, sem viés de módulo a corrigir. É também por isso que Python e Ruby abandonaram as APIs de faixa (`secrets.randbelow`, `SecureRandom.random_number`): mesma distribuição, um terço a um quinto do custo.

**Um pool é perigoso diante de `fork()`**, e isso não é hipótese: o `fork` duplica o pool, então pai e filho recebem os mesmos bytes e emitem UUIDs **idênticos**. A implementação em C lia através de um `FILE *`, e o buffer do stdio fazia exatamente isso, em toda execução. Cada linguagem se defende com o que tem:

| | proteção | custo por saque |
|---|---|---|
| Python | `os.register_at_fork`, o único hook oficial entre as seis | nenhum |
| Ruby | compara `Process.pid`, por não haver hook | ~95 ns |
| Rust | compara `std::process::id()` | ~2 ns |
| C | compara `getpid()` | ~3 ns |
| JavaScript | dispensa: Node não forka, e cada worker thread tem isolate e pool próprios | nenhum |
| Lua | **nenhuma possível**: não há `fork` nem como observá-lo. Risco latente, não pior que o do buffer do stdio que o pool substituiu, mas um host que forka precisa recarregar o módulo no filho |

Python, Rust e C zeram os bytes já consumidos, deixando na memória só entropia ainda não lida. Ruby e Lua não conseguem: seus pools são strings imutáveis.

---

## Exemplo prático, campo a campo

UUID gerado em **13/09/2026 às 02:26:10.253 UTC**:

```
01a09896-1ecd-7b03-bb26-376dea2187a4
```

| Campo | Valor hex | Bits | Significado |
|---|---|---|---|
| `unix_ts_ms` | `01a098961ecd` | 48 | Timestamp Unix em ms → 13/09/2026 02:26:10.253 UTC |
| `version` | `7` | 4 | Sempre `7`. É este nibble, logo após o segundo hífen, que identifica a versão só olhando a string |
| `rand_a` | `b03` | 12 | Bits aleatórios |
| `variant` | `10xx` (nibble `b` = `1011`) | 2 | Os 2 bits mais significativos do nibble marcam a variante RFC 9562 (`10`), por isso o primeiro caractere do grupo fica sempre entre `8` e `b` |
| `rand_b` | `b26376dea2187a4` | 62 | Bits aleatórios; reduzem a colisão entre UUIDs do mesmo milissegundo |

> `decode` reproduz esta tabela para qualquer UUIDv7:
>
> ```bash
> ruby    -r./uuid_v7 -e 'p UUIDv7.decode("01a09896-1ecd-7b03-bb26-376dea2187a4")'
> python3 -c 'import uuid_v7; print(uuid_v7.decode("01a09896-1ecd-7b03-bb26-376dea2187a4"))'
> ```

---

## Implementações neste repositório

Seis implementações da **v7**, cada uma usando apenas a biblioteca padrão da sua linguagem:

| Arquivo | Runtime | Como executar |
|---|---|---|
| [`uuid_v7.rb`](uuid_v7.rb) | Ruby | `ruby uuid_v7.rb` |
| [`uuid_v7.py`](uuid_v7.py) | Python 3 | `python3 uuid_v7.py` |
| [`uuid_v7.js`](uuid_v7.js) | Node 19+ | `node uuid_v7.js` |
| [`uuid_v7.lua`](uuid_v7.lua) | Lua 5.3+ | `lua uuid_v7.lua` |
| [`uuid_v7.rs`](uuid_v7.rs) | Rust 1.70+ | `rustc --edition 2021 -O uuid_v7.rs -o uuid_v7_rs && ./uuid_v7_rs` |
| [`uuid_v7.c`](uuid_v7.c) | C11 + POSIX | `cc -std=c11 -O2 -pthread uuid_v7.c -o uuid_v7_c && ./uuid_v7_c` |

As seis compartilham layout de campos, monotonicidade e saída, e são **compatíveis entre si**: um UUID gerado por qualquer uma decodifica igual nas outras cinco.

Rust e C são os casos compilados. Não há `Cargo.toml` nem makefile: o compilador é chamado direto no arquivo, que serve de binário da demonstração e de módulo reaproveitável (`mod uuid_v7;` no Rust, `-DUUIDV7_NO_MAIN` no C). Os dois binários têm nomes distintos de propósito, para que compilar um não sobrescreva o outro.

### API comum

A mesma superfície nas seis, mudando só a grafia (JavaScript usa camelCase; C prefixa tudo com `uuidv7_`, por não ter namespaces):

| Função | O que faz |
|---|---|
| `generate` | Um UUIDv7 monotônico (Método 2, RFC 9562 §6.2) |
| `generate_random` / `generateRandom` | Um UUIDv7 com `rand_a` e `rand_b` aleatórios (Método 1), que **não** garante ordenação dentro do mesmo milissegundo |
| `generate_bulk(n)` / `generateBulk(n)` | `n` UUIDs monotonicamente ordenados |
| `decode` | Decompõe um UUIDv7 nos seus campos |
| `valid?` / `is_valid` / `isValid` | `true` se for um UUIDv7 bem formado |

Três desvios que valem saber de antemão:

- **Rust** não tem exceções: `decode` devolve `Result<Decoded, DecodeError>`, com os campos numa struct em vez de um mapa, e `is_valid` é esse `Result` reduzido a booleano.
- **C** também não: `uuidv7_decode` devolve um código de status e preenche uma struct que **você** fornece. Nada ali aloca, todo produtor escreve num buffer seu de `UUIDV7_SIZE` bytes.
- O `timestamp` do **Python** é o único campo que pode vir `None`: o `datetime` para no ano 9999, enquanto os 48 bits de `unix_ts_ms` alcançam 10889-08-02. O UUID continua válido, só não tem data representável; as outras cinco imprimem o instante normalmente.

```ruby
require_relative 'uuid_v7'
UUIDv7.generate         # => "01a098b0-4420-71d4-83d6-582c6561f8d2"
```

```python
import uuid_v7
uuid_v7.generate()      # => "01a098b0-4477-70b4-9519-f2950ba49ead"
```

```javascript
const uuid_v7 = require("./uuid_v7");
uuid_v7.generate();     // => "01a098db-9f10-7516-b387-53dd678b03ea"
```

```lua
local uuid_v7 = require("uuid_v7")
uuid_v7.generate()      -- => "01a098b0-4138-7405-8dfc-89b4e3c48aa9"
```

```rust
mod uuid_v7;            // o arquivo ao lado, compilado junto

fn main() {
    println!("{}", uuid_v7::generate());   // => "01a0de04-e1d5-7299-a7f3-0322c0e38eed"
}
```

```c
#define UUIDV7_NO_MAIN  /* deixa de fora a main da demonstração */
#include "uuid_v7.c"

int main(void) {
    uuidv7_str u;
    uuidv7_generate(u);
    printf("%s\n", u);   /* => "01a0df35-f082-72b9-8c47-a9f8c46820ab" */
}
```

### Testes

Não há framework: cada arquivo traz uma demonstração autocontida no final, executada ao rodá-lo direto (no Rust e no C, ao compilar e executar o binário). Ela verifica geração, decodificação, ordenação de 100 000 UUIDs, acesso concorrente e o vetor do Apêndice A.6 da RFC.

> Os resultados saem como `true`/`false` e `✓`/`✗`, e o processo **não** retorna código de erro em caso de falha. É preciso ler a saída.

---

## Particularidades de cada linguagem

Em todos os casos, a limitação e o contorno estão documentados no cabeçalho do arquivo.

### JavaScript

Não tem tipo inteiro (números são exatos só até 2^53) e roda num único event loop:

- a montagem usa `BigInt`, então `decode` devolve `rand_b` (62 bits) como `BigInt`; `unix_ts_ms` (48) e `rand_a` (12) cabem num `Number`;
- não há mutex, porque há um só event loop (worker threads recebem isolate e gerador próprios);
- `generateBulk(3.0)` é aceito, já que `3.0` e `3` são o mesmo valor.

A entropia vem de `crypto.getRandomValues`, sem fallback: ou há CSPRNG, ou o código falha, nunca degradando para `Math.random`.

### Lua

Não tem inteiros de 128 bits, relógio de milissegundos na biblioteca padrão nem threads preemptivas:

- o UUID é montado grupo hexadecimal por grupo hexadecimal;
- o relógio usa `luaposix`/`luasocket` se instalados, senão interpola dentro do segundo (a ordenação nunca depende disso, só a precisão do timestamp);
- não há mutex, porque não há concorrência preemptiva a proteger.

A entropia vem de `/dev/urandom`; `math.random` entra só se ele não puder ser aberto e **não é criptograficamente seguro**, sendo a exceção prevista em §6.9 ("when a suitable CSPRNG is unavailable in the execution environment"). `entropy_source` e `clock_source` informam qual caminho está ativo. É também o único pool das seis sem defesa contra `fork` e, junto com o do Ruby, o único que não zera bytes consumidos.

### Rust

Tem `u128` nativo, então a montagem dispensa `BigInt` e grupos separados. As limitações estão na biblioteca padrão, que não traz CSPRNG, regex nem calendário:

- a entropia é `/dev/urandom` lido direto, sem fallback (como no JavaScript, não como no Lua): faltando o dispositivo, o processo entra em pânico. É o que restringe esta implementação, como a do C, a POSIX. O pool é `thread_local!` com inicializador `const`, então dispensa lock;
- o formato 8-4-4-4-12 é conferido dígito a dígito em `parse_hex128`, no lugar da regex que as outras quatro têm;
- `decode` devolve o `SystemTime` cru, porque `std` não sabe convertê-lo em data civil; a aritmética de calendário vive em `utc_string`, usada só na demonstração.

### C

Não tem inteiro de 128 bits no padrão (`__int128` é extensão), nem exceções, strings gerenciadas, regex, CSPRNG, tabela hash ou mutex portátil:

- o valor é um par de `uint64_t`, e a divisão é exata: a variante fica na fronteira do octeto 8, que é também a metade, então cada half guarda campos inteiros;
- `uuidv7_decode` devolve `uuidv7_status` e preenche struct do chamador; `uuidv7_strerror` faz o papel da mensagem de exceção;
- quem produz UUID escreve num buffer do chamador (`uuidv7_str`, 36 caracteres mais o terminador);
- o lock é `pthread_mutex_t`, porque o `<threads.h>` do C11 é opcional e a libc da Apple não o traz (`__STDC_NO_THREADS__`);
- o formato é conferido dígito a dígito em `uuidv7_parse`, e a demonstração checa unicidade com `qsort` mais comparação de vizinhos, por não haver tabela hash.

A entropia vem de `/dev/urandom` lido por descritor cru, e não por `FILE *`, para o stdio não pôr um segundo buffer sem proteção de fork atrás do pool. Sem fallback: faltando o dispositivo, o processo aborta. O teste de threads é o único do repositório verificável por máquina: com `cc -fsanitize=thread` a demonstração roda sem corrida detectada.

---

## Desempenho

`bench/run.sh` compara as seis nas quatro operações públicas. Referência (MacBook Intel i5-8259U 2,3 GHz, macOS 15.7.7; Ruby 4.0.3, Python 3.14.7, Node 26.4.0, Lua 5.5.1, rustc 1.98.1 com `-O`, Apple clang 17 com `-O2`), n = 100 000, mínimo de 5 execuções, **nanossegundos por operação**:

| operação | C | Rust | JS | Lua | Ruby | Python |
|---|---|---|---|---|---|---|
| `generate` | **105** | 164 | 663 | 3174 | 3960 | 3766 |
| `generate_random` | **124** | 169 | 749 | 3271 | 4182 | 4645 |
| `decode` | 299 | **260** | 1094 | 6377 | 2973 | 4088 |
| predicado | 98 | **38** | 1092 | 6422 | 2928 | 4133 |

O que a tabela mostra além da ordem esperada:

- desde o [pool de entropia](#pool-de-entropia), o gargalo do `generate` é a montagem da string, não o CSPRNG. Por isso Ruby, Python e Lua ficam nos ~3 µs: quase tudo ali é formatação de inteiro grande e concatenação;
- **nas duas compiladas, a montagem não usa a biblioteca de formatação**, que era o custo: em Rust, `format!("{:032x}")` mais um segundo `format!` para os hífens custavam 759 ns dos 853 do `generate`; em C, o `snprintf` custava 245 dos 348, por interpretar o template em tempo de execução. Emitindo os nibbles sobre as larguras de grupo, Rust caiu para 164 ns e C para 105, sem `unsafe` e sem mudar a saída. Nas quatro interpretadas o mesmo truque é **regressão**, de 5,6x no Lua a 11,8x no JS (6,6x no Python, 9,7x no Ruby), porque lá o `format` é código nativo e o laço de 32 passos não é;
- o predicado do Rust é o mais rápido (38 ns) porque `is_valid` deixou de passar pelo `decode`, que construía o resultado inteiro, com duas alocações, só para descartar. O do C já saía antes de preencher a struct ao receber `NULL`. Nas outras quatro, predicado ≈ `decode`;
- o `decode` do Lua é o mais lento por ser o único que formata o timestamp com `os.date` a cada chamada, em vez de só construir um objeto de tempo;
- os ~60 ns entre Rust e C no `generate` são uma alocação de heap de 36 bytes: o Rust devolve uma `String` própria, como cinco das seis, enquanto o C escreve no buffer do chamador. É escolha de API, não custo de segurança de ponteiro, que nem aparece: a versão com iteradores ficou mais rápida que a com tabela de índices, as duas em safe Rust.

As regras de que esses números dependem estão em [`bench/README.md`](bench/README.md). **Remeça na sua máquina** em vez de citar a tabela: ela vale para uma máquina e uma execução.

---

## Referências
- RFC 9562: https://www.rfc-editor.org/rfc/rfc9562.html
- RFC 4122 (obsoleta pela 9562): https://www.rfc-editor.org/rfc/rfc4122
- Cópia local para consulta offline: [`specs/rfc9562.txt`](specs/rfc9562.txt) (também em `.pdf` e `.mhtml`)
