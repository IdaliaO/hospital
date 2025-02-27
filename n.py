from werkzeug.security import generate_password_hash, check_password_hash

# Genera un hash de una contraseña conocida
password = '123456'
hashed_password = generate_password_hash(password)
print(f'Contraseña: {password}')
print(f'Hash: {hashed_password}')

# Verifica el hash
print(check_password_hash(hashed_password, password))
