import discord
import os
import base64
import logging

from discord.ext import commands
from dotenv import load_dotenv
from base64 import b64decode 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='/', intents=intents)

load_dotenv()

handler = logging.FileHandler(filename='discord.log', encoding='utf-8', mode='w')
token = os.getenv('DISCORD_TOKEN')

# This bot is made to take in user input and encode/decode using the AES 128 CBC Standard

@bot.event
async def on_ready():
    print('Online')

@bot.command(name='genKey')
async def genKey(ctx):
    key = Random.get_random_bytes(16)
    await ctx.send(f'Here is your key: {base64.b64encode(key).decode()}')


@bot.command(name='encrypt')
async def encrypt(ctx, key_b64, *, plaintext):
    # Example usage /encrypt <base64 key> <plaintext>
    try:
        key = base64.b64decode(key_b64)
        iv = Random.get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        encoded_ciphertext = base64.b64encode(iv + ciphertext).decode('utf-8')
        await ctx.send(f'Here is your encrypted message: {encoded_ciphertext}')
    except Exception as e:
        await ctx.send(f'Error: {str(e)}')

@bot.command(name='decrypt')
async def decrypt(ctx, key_b64, *, b64_ciphertext):
    # Example usage /decrypt <base64 key> <base64 ciphertext>

    try:
        key = base64.b64decode(key_b64)

        # Ciphertext (base64 -> bytes)
        blob = base64.b64decode(b64_ciphertext)

        # Assumes IV is prefixed
        iv, ct = blob[:16], blob[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)

        # Remove PKCS7 padding if present
        pad = pt[-1]
        if all(x == pad for x in pt[-pad:]):
            pt = pt[:-pad]
        await ctx.send(f'Here is your decrypted message: {pt.decode("utf-8", errors="ignore")}')
    except Exception as exc:
        # Most likely a bad key or bad ciphertext
        await ctx.send(f'Error: {str(exc)}')
        raise commands.CommandInvokeError(exc) from exc

bot.run(token, log_handler=handler, log_level=logging.DEBUG)
