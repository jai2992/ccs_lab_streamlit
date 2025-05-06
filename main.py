import streamlit as st
from typing import List
import numpy as np
import inspect
from caesar import caesar_cipher_encrypt, caesar_cipher_decrypt
from playfair import playfair_encrypt, playfair_decrypt
from hill import hill_encrypt, hill_decrypt
from railfence_row import rail_fence_encrypt_row_major, rail_fence_decrypt_row_major
from railfence_col import rail_fence_encrypt_col_major, rail_fence_decrypt_col_major
from des import des_encrypt, des_decrypt
from aes import aes_encrypt, aes_decrypt
from rsa import rsa_generate_keys, rsa_encrypt, rsa_decrypt
from diffie_hellman import diffie_hellman_shared_key
from sha import sha_hash
from md5 import md5_hash

# Helper for sidebar search and navigation
def sidebar_navigation(pages: List[str]):
    st.sidebar.title('Crypto Lab Navigation')
    search = st.sidebar.text_input('Search pages')
    filtered = [p for p in pages if search.lower() in p.lower()]
    page = st.sidebar.radio('Select a page', filtered if filtered else pages)
    return page

def get_code_no_comments(module_func):
    code = inspect.getsource(module_func)
    lines = code.split('\n')
    no_comments = [l for l in lines if not l.strip().startswith('#')]
    return '\n'.join(no_comments)

# Page functions
def page_caesar_cipher():
    st.header('1. Caesar Cipher')
    st.markdown('''**Caesar Cipher** is a substitution cipher where each letter in the plaintext is shifted by a fixed number (key). It is simple but insecure for modern use because of its small key space and vulnerability to frequency analysis.''')
    message = st.text_input('Enter message')
    key = st.number_input('Enter key (integer)', min_value=0, max_value=25, value=3)
    if st.button('Encrypt & Decrypt'):
        encrypted = caesar_cipher_encrypt(message, key)
        decrypted = caesar_cipher_decrypt(encrypted, key)
        st.write(f'**Encrypted:** {encrypted}')
        st.write(f'**Decrypted:** {decrypted}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    caesar_code = get_code_no_comments(caesar_cipher_encrypt) + '\n' + get_code_no_comments(caesar_cipher_decrypt)
    st.code(caesar_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': caesar_code}))

def page_playfair_cipher():
    st.header('2. Playfair Cipher')
    st.markdown('''**Playfair Cipher** is a digraph substitution cipher using a 5x5 matrix of letters constructed from a keyword. It encrypts pairs of letters, making frequency analysis more difficult than simple substitution ciphers. However, it is still vulnerable to modern cryptanalysis.''')
    message = st.text_input('Enter plaintext message', key='playfair_msg')
    keyword = st.text_input('Enter keyword (no spaces, letters only)', key='playfair_key')
    if st.button('Encrypt & Decrypt', key='playfair_btn'):
        encrypted = playfair_encrypt(message, keyword)
        decrypted = playfair_decrypt(encrypted, keyword)
        st.write(f'**Encrypted:** {encrypted}')
        st.write(f'**Decrypted:** {decrypted}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    playfair_code = (
        get_code_no_comments(playfair_encrypt)
        + '\n' + get_code_no_comments(playfair_decrypt)
        + '\n' + get_code_no_comments(__import__('playfair').playfair_generate_key_matrix)
        + '\n' + get_code_no_comments(__import__('playfair').playfair_find_position)
        + '\n' + get_code_no_comments(__import__('playfair').playfair_prepare_text)
    )
    st.code(playfair_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': playfair_code}))

def page_hill_cipher():
    st.header('3. Hill Cipher')
    st.markdown('''**Hill Cipher** is a polygraphic substitution cipher based on linear algebra. It uses matrix multiplication modulo 26 for encryption and requires the key matrix to be invertible mod 26 for decryption. Its strength lies in mixing multiple letters, but it is vulnerable to known-plaintext attacks and requires careful key selection.''')
    message = st.text_input('Enter plaintext message', key='hill_msg')
    key_str = st.text_input('Enter key matrix (comma-separated rows, e.g. "3 3 2,2 5 1,1 2 1")', key='hill_key')
    if st.button('Encrypt & Decrypt', key='hill_btn'):
        try:
            key_matrix = np.array([[int(num) for num in row.split()] for row in key_str.split(',')])
            encrypted = hill_encrypt(message, key_matrix)
            decrypted = hill_decrypt(encrypted, key_matrix)
            if decrypted is None:
                st.write('**Error:** Key matrix is not invertible mod 26.')
            else:
                st.write(f'**Encrypted:** {encrypted}')
                st.write(f'**Decrypted:** {decrypted}')
        except Exception as e:
            st.write(f'**Error:** {e}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    hill_code = (
        get_code_no_comments(hill_encrypt)
        + '\n' + get_code_no_comments(hill_decrypt)
        + '\n' + get_code_no_comments(__import__('hill').hill_prepare_text)
        + '\n' + get_code_no_comments(__import__('hill').hill_text_to_numbers)
        + '\n' + get_code_no_comments(__import__('hill').hill_numbers_to_text)
        + '\n' + get_code_no_comments(__import__('hill').modinv)
        + '\n' + get_code_no_comments(__import__('hill').hill_inverse_matrix)
    )
    st.code(hill_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': hill_code}))

def page_rail_fence_row():
    st.header('4. Rail Fence Cipher (Row-Major)')
    st.markdown('''**Rail Fence Cipher (Row-Major)** arranges the message in a zigzag pattern across a set number of rails (rows), then reads row by row for encryption. Decryption reconstructs the zigzag to recover the original message. It is simple and offers limited security.''')
    message = st.text_input('Enter message', key='rf_row_msg')
    rails = st.number_input('Enter number of rails', min_value=2, max_value=20, value=3, key='rf_row_rails')
    if st.button('Encrypt & Decrypt', key='rf_row_btn'):
        encrypted = rail_fence_encrypt_row_major(message, rails)
        decrypted = rail_fence_decrypt_row_major(encrypted, rails)
        st.write(f'**Encrypted:** {encrypted}')
        st.write(f'**Decrypted:** {decrypted}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    rf_row_code = get_code_no_comments(rail_fence_encrypt_row_major) + '\n' + get_code_no_comments(rail_fence_decrypt_row_major)
    st.code(rf_row_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': rf_row_code}))

def page_rail_fence_col():
    st.header('5. Rail Fence Cipher (Column-Major)')
    st.markdown('''**Rail Fence Cipher (Column-Major)** arranges the message into a matrix row by row, then reads column by column for encryption. Decryption reconstructs the matrix to recover the original message. This differs from the row-major approach by changing the reading order, but both are transposition ciphers with similar security.''')
    message = st.text_input('Enter message', key='rf_col_msg')
    cols = st.number_input('Enter number of columns', min_value=2, max_value=20, value=3, key='rf_col_cols')
    if st.button('Encrypt & Decrypt', key='rf_col_btn'):
        encrypted = rail_fence_encrypt_col_major(message, cols)
        decrypted = rail_fence_decrypt_col_major(encrypted, cols)
        st.write(f'**Encrypted:** {encrypted}')
        st.write(f'**Decrypted:** {decrypted}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    rf_col_code = get_code_no_comments(rail_fence_encrypt_col_major) + '\n' + get_code_no_comments(rail_fence_decrypt_col_major)
    st.code(rf_col_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': rf_col_code}))

def page_des():
    st.header('6. DES Algorithm')
    st.markdown('''**DES (Data Encryption Standard)** is a symmetric-key block cipher that encrypts data in 64-bit blocks using a 56-bit key (plus 8 parity bits). It is now considered insecure for many applications due to its short key length.''')
    message = st.text_input('Enter plaintext message', key='des_msg')
    key = st.text_input('Enter 8-character key', max_chars=8, key='des_key')
    if st.button('Encrypt & Decrypt', key='des_btn'):
        if len(key) != 8:
            st.write('**Error:** Key must be exactly 8 characters.')
        else:
            encrypted = des_encrypt(message, key)
            decrypted = des_decrypt(encrypted, key)
            st.write(f'**Encrypted:** {encrypted}')
            st.write(f'**Decrypted:** {decrypted}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    des_code = get_code_no_comments(des_encrypt) + '\n' + get_code_no_comments(des_decrypt)
    st.code(des_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': des_code}))

def page_aes():
    st.header('7. AES Algorithm')
    st.markdown('''**AES (Advanced Encryption Standard)** is a symmetric-key block cipher that encrypts data in 128-bit blocks using keys of 128, 192, or 256 bits. It is widely used and considered secure for most applications.''')
    message = st.text_input('Enter plaintext message', key='aes_msg')
    key = st.text_input('Enter key (16, 24, or 32 characters)', key='aes_key')
    if st.button('Encrypt & Decrypt', key='aes_btn'):
        if len(key) not in [16, 24, 32]:
            st.write('**Error:** Key must be 16, 24, or 32 characters.')
        else:
            encrypted = aes_encrypt(message, key)
            decrypted = aes_decrypt(encrypted, key)
            st.write(f'**Encrypted:** {encrypted}')
            st.write(f'**Decrypted:** {decrypted}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    aes_code = get_code_no_comments(aes_encrypt) + '\n' + get_code_no_comments(aes_decrypt)
    st.code(aes_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': aes_code}))

def page_rsa():
    st.header('8. RSA Algorithm')
    st.markdown('''**RSA** is a public-key cryptosystem that uses two large prime numbers to generate public and private keys. It is widely used for secure data transmission.''')
    p = st.number_input('Enter prime number p', min_value=3, value=61, key='rsa_p')
    q = st.number_input('Enter prime number q', min_value=3, value=53, key='rsa_q')
    plaintext = st.number_input('Enter plaintext (as integer)', min_value=0, value=65, key='rsa_plain')
    if st.button('Generate Keys & Encrypt/Decrypt', key='rsa_btn'):
        pub, priv = rsa_generate_keys(int(p), int(q))
        encrypted = rsa_encrypt(int(plaintext), pub)
        decrypted = rsa_decrypt(encrypted, priv)
        st.write(f'**Public Key:** {pub}')
        st.write(f'**Private Key:** {priv}')
        st.write(f'**Encrypted:** {encrypted}')
        st.write(f'**Decrypted:** {decrypted}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    rsa_code = get_code_no_comments(rsa_generate_keys) + '\n' + get_code_no_comments(rsa_encrypt) + '\n' + get_code_no_comments(rsa_decrypt)
    st.code(rsa_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': rsa_code}))

def page_diffie_hellman():
    st.header('9. Diffie-Hellman Key Exchange')
    st.markdown('''**Diffie-Hellman** is a key exchange algorithm that allows two parties to securely share a secret key over an insecure channel.''')
    p = st.number_input('Enter prime number p', min_value=3, value=23, key='dh_p')
    g = st.number_input('Enter primitive root g', min_value=2, value=5, key='dh_g')
    a = st.number_input('User A private key (a)', min_value=1, value=6, key='dh_a')
    b = st.number_input('User B private key (b)', min_value=1, value=15, key='dh_b')
    if st.button('Compute Shared Key', key='dh_btn'):
        A, B, key_a, key_b = diffie_hellman_shared_key(int(p), int(g), int(a), int(b))
        st.write(f'**User A Public Value (A):** {A}')
        st.write(f'**User B Public Value (B):** {B}')
        st.write(f'**User A Shared Key:** {key_a}')
        st.write(f'**User B Shared Key:** {key_b}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    dh_code = get_code_no_comments(diffie_hellman_shared_key)
    st.code(dh_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': dh_code}))

def page_sha():
    st.header('10. SHA Hash Algorithm')
    st.markdown('''**SHA (Secure Hash Algorithm)** is a family of cryptographic hash functions used for data integrity and digital signatures.''')
    message = st.text_input('Enter message to hash', key='sha_msg')
    variant = st.selectbox('SHA Variant', ['sha1', 'sha256', 'sha512'], key='sha_variant')
    if st.button('Hash', key='sha_btn'):
        digest = sha_hash(message, variant)
        st.write(f'**{variant.upper()} Hash:** {digest}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    sha_code = get_code_no_comments(sha_hash)
    st.code(sha_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': sha_code}))

def page_md5():
    st.header('11. MD5 Hash Algorithm')
    st.markdown('''**MD5 (Message Digest 5)** is a widely used hash function producing a 128-bit hash value. It is now considered broken and unsuitable for further use.''')
    message = st.text_input('Enter message to hash', key='md5_msg')
    if st.button('Hash', key='md5_btn'):
        digest = md5_hash(message)
        st.write(f'**MD5 Hash:** {digest}')
    st.markdown('---')
    st.markdown('**Algorithm Code (no comments):**')
    md5_code = get_code_no_comments(md5_hash)
    st.code(md5_code, language='python')
    st.button('Copy Code', on_click=lambda: st.session_state.update({'_code_to_copy': md5_code}))

# List of pages
pages = [
    '1. Caesar Cipher',
    '2. Playfair Cipher',
    '3. Hill Cipher',
    '4. Rail Fence Cipher (Row-Major)',
    '5. Rail Fence Cipher (Column-Major)',
    '6. DES Algorithm',
    '7. AES Algorithm',
    '8. RSA Algorithm',
    '9. Diffie-Hellman Key Exchange',
    '10. SHA Hash Algorithm',
    '11. MD5 Hash Algorithm'
]

# Main app logic
page = sidebar_navigation(pages)

if page == '1. Caesar Cipher':
    page_caesar_cipher()
elif page == '2. Playfair Cipher':
    page_playfair_cipher()
elif page == '3. Hill Cipher':
    page_hill_cipher()
elif page == '4. Rail Fence Cipher (Row-Major)':
    page_rail_fence_row()
elif page == '5. Rail Fence Cipher (Column-Major)':
    page_rail_fence_col()
elif page == '6. DES Algorithm':
    page_des()
elif page == '7. AES Algorithm':
    page_aes()
elif page == '8. RSA Algorithm':
    page_rsa()
elif page == '9. Diffie-Hellman Key Exchange':
    page_diffie_hellman()
elif page == '10. SHA Hash Algorithm':
    page_sha()
elif page == '11. MD5 Hash Algorithm':
    page_md5()