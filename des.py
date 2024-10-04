from time import sleep

# Importando as constantes necessárias para o algoritmo DES
from constants import (
    e_box_table,  # Tabela de expansão
    ip_inverse_table,  # Tabela de permutação inversa
    ip_table,  # Tabela de permutação
    p_box_table,  # Tabela de permutação P
    pc1_table,  # Tabela de permutação PC1
    pc2_table,  # Tabela de permutação PC2
    s_boxes,  # Caixas de substituição S
    shift_rounds,  # Número de rodadas de shift
)

KEY_8_BYTES = "DESCRYPT"


# Função para converter uma string em binário
def str_to_bin(user_input):
    """
    Converte uma string em binário, dividindo-a em blocos de 8 bytes.

    Args:
        user_input (str): A string a ser convertida.

    Returns:
        list: Uma lista de strings binárias, cada uma representando um bloco da string de entrada.
    """
    binary_representation = []
    for i in range(0, len(user_input), 8):
        block = user_input[i : i + 8]
        binary_block = ""

        for char in block:
            # Converte cada caractere em binário e adiciona ao bloco
            binary_char = format(ord(char), "08b")
            binary_block += binary_char

        # Adiciona o bloco à lista de representações binárias
        binary_representation.append(
            binary_block.ljust(64, "0")
        )  # Preenche a string com 0 até ter 8 bytes

    return binary_representation


# Função para converter uma string binária em ASCII
def binary_to_ascii(binary_str):
    """
    Converte uma string binária em ASCII.

    Args:
        binary_str (str): A string binária a ser convertida.

    Returns:
        str: A string ASCII correspondente à string binária de entrada.
    """
    ascii_str = "".join(
        [chr(int(binary_str[i : i + 8], 2)) for i in range(0, len(binary_str), 8)]
    )

    return ascii_str


# Função para realizar a permutação inicial
def ip_on_binary_rep(binary_representation):
    """
    Realiza a permutação inicial em uma string binária.

    Args:
        binary_representation (str): A string binária a ser permutada.

    Returns:
        str: A string binária permutada.
    """
    ip_result = [None] * 64

    for i in range(64):
        ip_result[i] = binary_representation[ip_table[i] - 1]
    ip_result_str = "".join(ip_result)

    return ip_result_str


# Função para converter a chave em binário
def key_in_binary_conv():
    """
    Converte a chave em binário.

    Returns:
        str: A chave em binário.
    """
    binary_representation_key = ""

    for char in KEY_8_BYTES:
        # Converte cada caractere em binário e adiciona à chave
        binary_key = format(ord(char), "08b")
        binary_representation_key += binary_key

    return binary_representation_key


# Função para gerar as chaves de rodada
def generate_round_keys():
    """
    Gera as chaves de rodada para o algoritmo DES.

    Returns:
        list: Uma lista de chaves de rodada.
    """
    binary_representation_key = key_in_binary_conv()
    pc1_key_str = "".join(binary_representation_key[bit - 1] for bit in pc1_table)
    c0 = pc1_key_str[:28]
    d0 = pc1_key_str[28:]
    round_keys = []

    for round_num in range(16):
        # Realiza o shift circular nas metades da chave
        c0 = c0[shift_rounds[round_num] :] + c0[: shift_rounds[round_num]]
        d0 = d0[shift_rounds[round_num] :] + d0[: shift_rounds[round_num]]
        # Concatena as metades da chave
        cd_concatenated = c0 + d0
        # Aplica a permutação PC2
        round_key = "".join(cd_concatenated[bit - 1] for bit in pc2_table)
        # Adiciona a chave de rodada à lista
        round_keys.append(round_key)

    return round_keys


# Função para realizar a criptografia de um bloco
def encryption_block(binary_block):
    """
    Realiza a criptografia de um bloco usando o algoritmo DES.

    Args:
        binary_block (str): O bloco a ser cri ptografado.

    Returns:
        str: O bloco criptografado.
    """
    round_keys = generate_round_keys()
    ip_result = ip_on_binary_rep(binary_block)
    left_half = ip_result[:32]
    right_half = ip_result[32:]

    for round_num in range(16):
        # Realiza a expansão da metade direita
        expanded_right_half = "".join(right_half[e_box_table[i] - 1] for i in range(48))
        # Realiza o XOR com a chave de rodada
        xor_result = "".join(
            str(int(expanded_right_half[i]) ^ int(round_keys[round_num][i]))
            for i in range(48)
        )
        # Divide o resultado em blocos de 6 bits
        s_box_input = [xor_result[i : i + 6] for i in range(0, 48, 6)]
        # Aplica as caixas de substituição S
        s_box_output = "".join(s_boxes[i][int(s_box_input[i], 2)] for i in range(8))
        # Realiza a permutação P
        p_box_output = "".join(s_box_output[p_box_table[i] - 1] for i in range(32))
        # Realiza o XOR com a metade esquerda
        left_half = "".join(
            str(int(left_half[i]) ^ int(p_box_output[i])) for i in range(32)
        )
        # Troca as metades
        left_half, right_half = right_half, left_half

    # Realiza a permutação inversa
    ip_inverse_result = "".join(right_half[ip_inverse_table[i] - 1] for i in range(64))

    return ip_inverse_result


# Função para realizar a criptografia de uma string
def encryption(user_input):
    """
    Realiza a criptografia de uma string usando o algoritmo DES.

    Args:
        user_input (str): A string a ser criptografada.

    Returns:
        str: A string criptografada.
    """
    binary_representation = str_to_bin(user_input)
    encrypted_blocks = [encryption_block(block) for block in binary_representation]
    encrypted_text = "".join(encrypted_blocks)

    return encrypted_text


# Função para realizar a descriptografia de um bloco
def decryption_block(binary_block):
    """
    Realiza a descriptografia de um bloco usando o algoritmo DES.

    Args:
        binary_block (str): O bloco a ser descriptografado.

    Returns:
        str: O bloco descriptografado.
    """
    round_keys = generate_round_keys()
    ip_result = ip_on_binary_rep(binary_block)
    left_half = ip_result[:32]
    right_half = ip_result[32:]

    for round_num in range(15, -1, -1):
        # Realiza a expansão da metade direita
        expanded_right_half = "".join(right_half[e_box_table[i] - 1] for i in range(48))
        # Realiza o XOR com a chave de rodada
        xor_result = "".join(
            str(int(expanded_right_half[i]) ^ int(round_keys[round_num][i]))
            for i in range(48)
        )
        # Divide o resultado em blocos de 6 bits
        s_box_input = [xor_result[i : i + 6] for i in range(0, 48, 6)]
        # Aplica as caixas de substituição S
        s_box_output = "".join(s_boxes[i][int(s_box_input[i], 2)] for i in range(8))
        # Realiza a permutação P
        p_box_output = "".join(s_box_output[p_box_table[i] - 1] for i in range(32))
        # Realiza o XOR com a metade esquerda
        left_half = "".join(
            str(int(left_half[i]) ^ int(p_box_output[i])) for i in range(32)
        )
        # Troca as metades
        left_half, right_half = right_half, left_half

    # Realiza a permutação inversa
    ip_inverse_result = "".join(right_half[ip_inverse_table[i] - 1] for i in range(64))

    return ip_inverse_result


# Função para realizar a descriptografia de uma string
def decryption(encrypted_text):
    """
    Realiza a descriptografia de uma string usando o algoritmo DES.

    Args:
        encrypted_text (str): A string a ser descriptografada.

    Returns:
        str: A string descriptografada.
    """
    binary_blocks = [
        encrypted_text[i : i + 64] for i in range(0, len(encrypted_text), 64)
    ]
    decrypted_blocks = [decryption_block(block) for block in binary_blocks]
    decrypted_text = "".join(decrypted_blocks)
    
    return binary_to_ascii(decrypted_text)


def main():
    user_input = input("Digite um texto para ser criptografado: ")
    print("Chave utilizada: ", KEY_8_BYTES, "\n")
    sleep(2)
    encrypted_text = encryption(user_input)
    print("Texto criptografado em binário:", encrypted_text, "\n")
    sleep(2)
    encrypted_ascii = binary_to_ascii(encrypted_text)
    print("Texto criptografado em ASCII:", encrypted_ascii, "\n")
    sleep(2)

    decrypted_text = decryption(encrypted_text)
    print("Texto descriptografado:", decrypted_text, "\n")


if __name__ == "__main__":
    main()
