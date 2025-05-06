def rail_fence_encrypt_row_major(text, rails):
    if rails <= 1:
        return text
    fence = ['' for _ in range(rails)]
    rail = 0
    direction = 1
    for char in text:
        fence[rail] += char
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    return ''.join(fence)

def rail_fence_decrypt_row_major(cipher, rails):
    if rails <= 1:
        return cipher
    pattern = [0] * len(cipher)
    rail = 0
    direction = 1
    for i in range(len(cipher)):
        pattern[i] = rail
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    rail_counts = [pattern.count(r) for r in range(rails)]
    rails_content = []
    idx = 0
    for count in rail_counts:
        rails_content.append(list(cipher[idx:idx+count]))
        idx += count
    result = ''
    rail_indices = [0] * rails
    for r in pattern:
        result += rails_content[r][rail_indices[r]]
        rail_indices[r] += 1
    return result
