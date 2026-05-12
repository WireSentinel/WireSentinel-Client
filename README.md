# WireSentinel Client

Cliente em C responsável por capturar pacotes de rede via raw socket, extrair metadados relevantes, montar eventos estruturados e enviar os dados em lote para o backend WireSentinel.

## Arquitetura planejada

O client será organizado em um pipeline multi-thread separado em três responsabilidades principais:

- Thread 1: captura de pacotes
- Thread 2: parsing e montagem da estrutura final
- Thread 3: serialização em JSON e envio HTTP

O fluxo planejado é:

Thread 1 recebe pacotes da interface de rede usando `recvfrom()` e insere os pacotes brutos em uma fila de processamento.

Thread 2 consome essa fila de pacotes brutos, realiza o parsing dos protocolos suportados e monta uma estrutura `FullNetworkPacket` com os dados já tratados.

Thread 3 consome periodicamente a fila de estruturas, monta um JSON em lote e envia os dados ao backend via HTTP POST.

Durante o consumo da fila de estruturas, a Thread 3 bloqueia temporariamente a Thread 2 usando mutex, evitando escrita simultânea na fila enquanto os dados estão sendo consumidos e serializados.

## Estrutura

- [x] Criar estrutura inicial do projeto
- [x] Configurar build com CMake
- [x] Separar headers e arquivos fonte
- [x] Organizar módulos principais do client

## Captura

- [x] Abrir socket RAW
- [x] Capturar pacotes da interface
- [x] Parsing de Ethernet
- [x] Parsing de IPv4
- [x] Parsing de IPv6
- [x] Parsing de ARP
- [x] Parsing de UDP
- [x] Parsing de TCP
- [ ] Tratar extension headers do IPv6
- [ ] Melhorar validações de tamanho antes do parsing

## Extração de dados

- [ ] Extrair domínio via DNS
- [x] Extrair Host HTTP
- [ ] Extrair SNI TLS
- [x] Ignorar payload irrelevante
- [x] Identificar aplicação por porta TCP/UDP
- [x] Utilizar tabela local de serviços conhecidos
- [ ] Melhorar identificação de protocolos de aplicação

## Eventos / Estruturas

- [x] Criar struct principal de pacote/evento
- [x] Adicionar timestamp
- [x] Adicionar dados de camada de rede
- [x] Adicionar dados de camada de transporte
- [x] Adicionar dados de aplicação quando disponíveis
- [ ] Adicionar identificação da máquina
- [ ] Padronizar campos opcionais
- [ ] Revisar nomes finais do payload enviado ao backend

## Pipeline multi-thread

- [ ] Criar Thread 1 para captura com `recvfrom()`
- [ ] Criar Thread 2 para parsing dos pacotes
- [ ] Criar Thread 3 para montagem de JSON e envio HTTP
- [ ] Implementar fila de pacotes brutos
- [ ] Implementar fila de `FullNetworkPacket`
- [ ] Adicionar mutex na fila de pacotes brutos
- [ ] Adicionar mutex na fila de estruturas
- [ ] Definir estratégia de consumo contínuo da Thread 2
- [ ] Definir janela de envio da Thread 3
- [ ] Garantir liberação correta de memória entre as threads

## Buffer / Filas

- [ ] Implementar buffer em memória para pacotes brutos
- [ ] Implementar fila em memória para structs processadas
- [ ] Definir janela de envio
- [ ] Definir limite máximo da fila bruta
- [ ] Definir limite máximo da fila de structs
- [ ] Implementar descarte seguro
- [ ] Contabilizar pacotes descartados
- [ ] Evitar crescimento infinito de memória

## Serialização

- [x] Criar JSON manual
- [x] Garantir escaping correto
- [x] Estruturar payload em lote
- [x] Adicionar HMAC ao envio
- [x] Adicionar timestamp da requisição
- [ ] Integrar serialização com a fila de structs
- [ ] Garantir limpeza das structs após serialização
- [ ] Validar payload final enviado ao backend

## Comunicação

- [x] Criar cliente HTTP com socket
- [x] Montar requisição POST
- [x] Adicionar headers HTTP
- [x] Enviar dados ao servidor
- [x] Adicionar autenticação por HMAC
- [ ] Ler resposta do backend
- [ ] Tratar códigos HTTP de erro
- [ ] Separar falha de conexão de falha de aplicação
- [ ] Ajustar timeout de envio

## Resiliência

- [x] Tratar falhas de conexão
- [x] Implementar retry simples
- [ ] Implementar política de descarte
- [ ] Definir comportamento quando o backend estiver fora
- [ ] Definir limite de tentativas por lote
- [ ] Evitar bloqueio da captura por falha no envio
- [ ] Registrar falhas internas do client

## Métricas internas planejadas

- [ ] Contar pacotes recebidos
- [ ] Contar pacotes processados
- [ ] Contar pacotes ignorados
- [ ] Contar pacotes descartados por fila cheia
- [ ] Contar lotes JSON enviados
- [ ] Contar falhas de envio
- [ ] Contar retries realizados
