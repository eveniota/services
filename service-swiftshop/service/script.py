import base64
import hashpumpy

# Correct secret key and its length (32 bytes)
secret = "shop_merchant_promokey_prod_32b!"
secret_length = len(secret)  # 32

original_message = "user=alice&credit=10&tier=standard"
original_signature = "305fa8408bb76b2d48c7b6e9326c14dc3522ebb84b0224356bde4a30cdeaeb36"
data_to_append = "&tier=executive"

# Perform the length extension attack
res1, res2 = hashpumpy.hashpump(
    original_signature,
    original_message,
    data_to_append,
    secret_length
)

# Handle output types (bytes vs str across hashpumpy versions)
if isinstance(res1, bytes):
    forged_bytes, new_signature = res1, res2
else:
    new_signature, forged_bytes = res1, res2.encode('latin1') if isinstance(res2, str) else res2

# Base64 encode the full forged message (including binary padding)
encoded_payload = base64.b64encode(forged_bytes).decode('utf-8')

# Combine into the final token format: Payload.Signature
final_token = f"{encoded_payload}.{new_signature}"

print("[-] Final Token:")
print(final_token)
