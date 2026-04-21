# WireSentinel Client

## Estrutura
- [ ] Criar estrutura inicial do projeto
- [ ] Configurar build (Makefile)

## Captura
- [ ] Abrir socket RAW
- [ ] Capturar pacotes da interface
- [ ] Parsing de IP
- [ ] Parsing de UDP
- [ ] Parsing de TCP

## Extração de dados
- [ ] Extrair domínio via DNS
- [ ] Extrair Host (HTTP)
- [ ] Extrair SNI (TLS)
- [ ] Ignorar payload irrelevante

## Eventos
- [ ] Criar struct de evento
- [ ] Adicionar timestamp
- [ ] Adicionar identificação da máquina

## Buffer
- [ ] Implementar buffer em memória
- [ ] Definir janela de envio
- [ ] Definir limite máximo
- [ ] Implementar descarte seguro

## Serialização
- [ ] Criar JSON manual
- [ ] Garantir escaping correto
- [ ] Estruturar payload em lote

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

## Observabilidade
- [ ] Adicionar logs básicos
- [ ] Medir uso de memória
- [ ] Medir uso de CPU
