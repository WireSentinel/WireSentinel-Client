# WireSentinel Client

## Estrutura
- [x] Criar estrutura inicial do projeto
- [ ] Configurar build (Makefile)

## Captura
- [x] Abrir socket RAW
- [x] Capturar pacotes da interface
- [x] Parsing de IPV4
- [x] Parsing de IPV6
- [x] Parsing de ARP
- [x] Parsing de UDP
- [x] Parsing de TCP

## Extração de dados
- [ ] Extrair domínio via DNS
- [x] Extrair Host (HTTP)
- [ ] Extrair SNI (TLS)
- [x] Ignorar payload irrelevante

## Eventos
- [x] Criar struct de evento
- [x] Adicionar timestamp
- [ ] Adicionar identificação da máquina

## Buffer
- [ ] Implementar buffer em memória
- [ ] Definir janela de envio
- [ ] Definir limite máximo
- [ ] Implementar descarte seguro

## Serialização
- [x] Criar JSON manual
- [x] Garantir escaping correto
- [x] Estruturar payload em lote

## Comunicação
- [ ] Criar cliente HTTP com socket
- [ ] Montar requisição POST
- [ ] Adicionar headers HTTP
- [ ] Enviar dados ao servidor
- [ ] Ler resposta do backend

## Resiliência
- [ ] Tratar falhas de conexão
- [ ] Implementar retry simples
- [ ] Implementar política de descarte
