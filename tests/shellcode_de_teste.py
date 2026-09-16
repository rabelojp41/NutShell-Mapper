"""
Gerador de shellcode inerte para exercitar o caminho de stack strings.

Por que isto existe: o diferencial do FLOSS e recuperar strings que o
malware monta em tempo de execucao e que nunca aparecem literais no
arquivo. Todo o resto do projeto foi validado com binarios reais, mas esse
caminho especifico nunca rodou com dado de verdade - binario benigno nao
tem stack string, e usar malware real como fixture de teste esta fora de
questao.

A solucao e emitir o padrao canonico de stack string diretamente em bytes
de maquina x86. Nao ha compilador envolvido, o artefato e determinista e
cabe no repositorio.

O QUE O CODIGO GERADO FAZ: monta um prologo de funcao, escreve a string
byte a byte na pilha atraves de instrucoes `mov`, restaura a pilha e
retorna. Nada mais. Nao ha chamada de sistema, nao ha salto para endereco
externo, nao ha leitura de arquivo nem de rede. Se executado, ele mexe em
alguns bytes da propria pilha e devolve o controle. E inerte por
construcao, e existe apenas para o emulador do FLOSS ter o que recuperar.
"""

from __future__ import annotations

import struct


def _mov_dword_para_pilha(deslocamento: int, valor: bytes) -> bytes:
    """
    Emite `mov dword [ebp+deslocamento], imm32`.

    Codificacao: C7 /0 com modrm 45 (base EBP, deslocamento de 1 byte),
    seguido do deslocamento com sinal e do imediato de 4 bytes.
    """
    if not -128 <= deslocamento <= 127:
        raise ValueError("deslocamento nao cabe em um byte com sinal")
    if len(valor) != 4:
        raise ValueError("o imediato precisa ter exatamente 4 bytes")

    return b"\xc7\x45" + struct.pack("<b", deslocamento) + valor


def gerar_stack_string_x86(texto: str, quadro: int = 0x40) -> bytes:
    """
    Gera shellcode x86 de 32 bits que monta `texto` na pilha.

    A string e escrita em blocos de 4 bytes por instrucoes `mov` com
    imediato - exatamente o padrao que compiladores produzem para string
    curta e que malware usa para esconder indicadores da varredura estatica.
    Os caracteres ficam embutidos como imediatos das instrucoes, nunca como
    uma sequencia contigua no arquivo, entao um `strings` comum nao os ve.

    Args:
        texto: o conteudo a montar na pilha (ASCII).
        quadro: tamanho do quadro de pilha reservado.

    Returns:
        Os bytes do shellcode.
    """
    dados = texto.encode("ascii") + b"\x00"
    # Completa para multiplo de 4, porque cada instrucao escreve 4 bytes.
    dados += b"\x00" * (-len(dados) % 4)

    if len(dados) > quadro:
        raise ValueError(
            f"a string ocupa {len(dados)} bytes e nao cabe num quadro de {quadro}"
        )

    codigo = bytearray()
    codigo += b"\x55"                                  # push ebp
    codigo += b"\x89\xe5"                              # mov ebp, esp
    codigo += b"\x83\xec" + struct.pack("<B", quadro)  # sub esp, quadro

    inicio = -quadro
    for i in range(0, len(dados), 4):
        codigo += _mov_dword_para_pilha(inicio + i, dados[i : i + 4])

    # lea eax, [ebp-quadro] — deixa o endereco da string em EAX, para o
    # emulador ver que ela e usada, e nao apenas escrita e descartada.
    codigo += b"\x8d\x45" + struct.pack("<b", inicio)

    codigo += b"\x89\xec"                              # mov esp, ebp
    codigo += b"\x5d"                                  # pop ebp
    codigo += b"\xc3"                                  # ret

    return bytes(codigo)


# O FLOSS desiste da analise inteira quando o arquivo nao tem nenhuma
# string estatica: em floss/main.py ha um `if not static_strings: return 0`,
# que sai silenciosamente com codigo 0 e sem saida nenhuma. Como o shellcode
# gerado esconde tudo em imediatos de instrucao, por construcao ele nao tem
# string estatica alguma - e sem esta ancora o FLOSS nao analisaria nada,
# nem as stack strings.
ANCORA_ESTATICA = b"RabMapper amostra de teste inerte"


def gerar_amostra(textos: list[str], com_ancora: bool = True) -> bytes:
    """
    Gera um shellcode com uma funcao por string, mais um ponto de entrada
    que chama todas.

    O ponto de entrada existe por causa de como o vivisect descobre codigo:
    ele parte do offset 0 e segue o fluxo. Funcoes apenas enfileiradas uma
    apos a outra nao sao alcancadas - so a primeira seria analisada, e o
    FLOSS emula funcao por funcao para achar stack string. O dispatcher com
    `call` da ao vivisect o grafo de chamadas de que ele precisa.

    Args:
        textos: as strings a montar na pilha.
        com_ancora: acrescenta uma string estatica no fim. Necessario
            porque o FLOSS encerra sem analisar nada quando o arquivo nao
            tem string estatica alguma. A ancora fica depois do ultimo
            `ret`, entao nunca e executada.
    """
    funcoes = [gerar_stack_string_x86(t) for t in textos]

    # Cada `call rel32` ocupa 5 bytes; o `ret` do dispatcher, 1.
    tamanho_do_dispatcher = 5 * len(funcoes) + 1

    dispatcher = bytearray()
    deslocamento_acumulado = 0
    for i, funcao in enumerate(funcoes):
        # rel32 e relativo ao fim da propria instrucao `call`.
        fim_do_call = 5 * (i + 1)
        destino = tamanho_do_dispatcher + deslocamento_acumulado
        dispatcher += b"\xe8" + struct.pack("<i", destino - fim_do_call)
        deslocamento_acumulado += len(funcao)
    dispatcher += b"\xc3"  # ret

    codigo = bytes(dispatcher) + b"".join(funcoes)

    if com_ancora:
        codigo += bytes([0]) + ANCORA_ESTATICA + bytes([0])
    return codigo


if __name__ == "__main__":
    import sys
    from pathlib import Path

    destino = Path(sys.argv[1] if len(sys.argv) > 1 else "stack_strings.bin")
    amostra = gerar_amostra(
        [
            "http://stack-c2.top/gate.php",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "cmd.exe /c whoami",
        ]
    )
    destino.write_bytes(amostra)
    print(f"{destino}: {len(amostra)} bytes")
