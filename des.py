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
    binary_representation = ""

    for char in user_input:
        # Converte cada caractere em seu valor ASCII e, em seguida, em uma string binária de 1 byte.
        binary_char = format(ord(char), "08b")
        binary_representation += binary_char
        binary_representation = binary_representation[:64]

    # Limita a representação binária à 64 bits e completa com zeros à esquerda se necessário.
    binary_representation = binary_representation[:64].ljust(64, "0")

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

    # Itera sobre a string binária em grupos de 8 bits, converte cada grupo em um caractere ASCII e junta todos os caracteres em uma string.
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
        c0 = c0[shift_rounds[round_num] :] + c0[: shift_rounds[round_num]]
        d0 = d0[shift_rounds[round_num] :] + d0[: shift_rounds[round_num]]
        cd_concatenated = c0 + d0

        round_key = "".join(cd_concatenated[bit - 1] for bit in pc2_table)

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
    binary_rep_of_input = str_to_bin(binary_block)
    round_keys = generate_round_keys()

    ip_result_str = ip_on_binary_rep(binary_rep_of_input)

    lpt = ip_result_str[:32]
    rpt = ip_result_str[32:]

    for round_num in range(16):
        expanded_result = [rpt[i - 1] for i in e_box_table]

        expanded_result_str = "".join(expanded_result)

        round_key_str = round_keys[round_num]

        xor_result_str = ""
        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))

        # Divide o resultado do XOR em grupos de 6 bits
        six_bit_groups = [xor_result_str[i : i + 6] for i in range(0, 48, 6)]

        s_box_substituted = ""

        for i in range(8):
            # Seleciona os bits de linha da tabela S-Box
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
            # Seleciona os bits de coluna da tabela S-Box.
            col_bits = int(six_bit_groups[i][1:-1], 2)

            s_box_value = s_boxes[i][row_bits][col_bits]

            # Adiciona o valor formatado em 4 bits à substituição.
            s_box_substituted += format(s_box_value, "04b")

        p_box_result = [s_box_substituted[i - 1] for i in p_box_table]

        lpt_list = list(lpt)

        # Realiza o XOR entre a parte lpt do bloco e a string permutada.
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

        new_rpt_str = "".join(new_rpt)

        lpt = rpt
        rpt = new_rpt_str

    final_result = rpt + lpt
    final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]
    final_cipher_str = "".join(final_cipher)
    final_cipher_ascii = binary_to_ascii(final_cipher_str)

    return final_cipher_ascii


# Função para realizar a criptografia de uma string
def encryption(user_input):
    """
    Realiza a criptografia de uma string usando o algoritmo DES.

    Args:
        user_input (str): A string a ser criptografada.

    Returns:
        str: A string criptografada.
    """

    # Divide o texto em blocos de 8 bytes
    encrypted_blocks = [
        encryption_block(user_input[i : i + 8]) for i in range(0, len(user_input), 8)
    ]
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
    binary_rep_of_input = str_to_bin(binary_block)
    round_keys = generate_round_keys()

    ip_dec_result_str = ip_on_binary_rep(binary_rep_of_input)

    lpt = ip_dec_result_str[:32]
    rpt = ip_dec_result_str[32:]

    for round_num in range(16):
        expanded_result = [rpt[i - 1] for i in e_box_table]

        expanded_result_str = "".join(expanded_result)

        # Seleciona a chave de rodada atual.
        round_key_str = round_keys[15 - round_num]

        xor_result_str = ""
        for i in range(48):
            # Realiza o XOR entre a chave de rodada e a parte expandida do bloco.
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))

        six_bit_groups = [xor_result_str[i : i + 6] for i in range(0, 48, 6)]

        s_box_substituted = ""

        for i in range(8):
            # Seleciona os bits de linha da tabela S-Box.
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
            # Seleciona os bits de coluna da tabela S-Box.
            col_bits = int(six_bit_groups[i][1:-1], 2)

            s_box_value = s_boxes[i][row_bits][col_bits]

            # Adiciona o valor formatado em 4 bits à substituição.
            s_box_substituted += format(s_box_value, "04b")

        p_box_result = [s_box_substituted[i - 1] for i in p_box_table]

        lpt_list = list(lpt)

        # Realiza o XOR entre a parte lpt do bloco e a string permutada.
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

        new_rpt_str = "".join(new_rpt)

        lpt = rpt
        rpt = new_rpt_str

    final_result = rpt + lpt
    final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]

    final_cipher_str = "".join(final_cipher)

    final_cipher_ascii = binary_to_ascii(final_cipher_str)

    return final_cipher_ascii


# Função para realizar a descriptografia de uma string
def decryption(encrypted_text):
    """
    Realiza a descriptografia de uma string usando o algoritmo DES.

    Args:
        encrypted_text (str): A string a ser descriptografada.

    Returns:
        str: A string descriptografada.
    """
    decryption_blocks = [
        decryption_block(encrypted_text[i : i + 8])
        for i in range(0, len(encrypted_text), 8)
    ]
    decrypted_text = "".join(decryption_blocks)

    return decrypted_text


def main():
    user_input = input("Digite um texto para ser criptografado: ")
    print("Chave utilizada: ", KEY_8_BYTES, "\n")
    sleep(2)
    encrypted_text = encryption(user_input)
    bin_enc_text = "".join(format(ord(char), "08b") for char in encrypted_text)
    print(
        "Texto criptografado em binário:",
        bin_enc_text,
        "\n",
    )
    sleep(2)
    encrypted_ascii = binary_to_ascii(bin_enc_text)
    print("Texto criptografado em ASCII:", encrypted_ascii, "\n")
    sleep(2)

    decrypted_text = decryption(encrypted_text)
    print("Texto descriptografado:", decrypted_text, "\n")


if __name__ == "__main__":
    main()
