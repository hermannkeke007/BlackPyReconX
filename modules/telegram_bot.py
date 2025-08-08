
import os
import sys
import json
import asyncio
import requests
import socket
import time

# Add project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    ConversationHandler,
    CallbackQueryHandler,
    MessageHandler,
    filters,
    ContextTypes,
)
from dotenv import load_dotenv
load_dotenv()

from modules import osint, scanner, exploit_web, reporting, exfiltration, utils, dos, bruteforce, crypto_tools

# États pour la conversation
(SELECTING_ACTION, AWAITING_TARGET, AWAITING_CONFIRMATION,
AWAITING_DOS_PORT, AWAITING_DOS_DURATION, AWAITING_DOS_TOR,
AWAITING_BRUTEFORCE_SERVICE, AWAITING_BRUTEFORCE_TYPE,
AWAITING_BRUTEFORCE_USERLIST, AWAITING_BRUTEFORCE_PASSLIST,
AWAITING_BRUTEFORCE_USERNAME, AWAITING_BRUTEFORCE_CHARSET,
AWAITING_BRUTEFORCE_MIN_LEN, AWAITING_BRUTEFORCE_MAX_LEN,
AWAITING_BRUTEFORCE_URL, AWAITING_BRUTEFORCE_USER_FIELD,
AWAITING_BRUTEFORCE_PASS_FIELD, AWAITING_BRUTEFORCE_FAIL_STRING,
AWAITING_STOP,
SELECTING_STEGANO_ACTION, AWAITING_STEGANO_IMAGE_HIDE,
AWAITING_STEGANO_SECRET_FILE, AWAITING_STEGANO_IMAGE_REVEAL) = range(23)

# --- MENUS ET HANDLERS DE BASE ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    keyboard = [
        [InlineKeyboardButton("🔍 OSINT", callback_data='osint'),
         InlineKeyboardButton("📡 Scan de Ports", callback_data='scan')],
        [InlineKeyboardButton("🌐 Scan Web", callback_data='web'),
         InlineKeyboardButton("📄 Rapport", callback_data='report')],
        [InlineKeyboardButton("📦 Exfiltration", callback_data='exfil'),
         InlineKeyboardButton("💥 Attaque DoS", callback_data='dos'),
         InlineKeyboardButton("💪 Force Brute", callback_data='bruteforce')],
        [InlineKeyboardButton("🖼️ Stéganographie", callback_data='stegano'),
         InlineKeyboardButton("🔒 Gérer TOR", callback_data='tor_menu')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    text = "🤖 *Bienvenue sur le bot de contrôle BlackPyReconX*\n\nChoisissez une action à exécuter :"

    if update.message:
        await update.message.reply_text(text, reply_markup=reply_markup, parse_mode='Markdown')
    elif update.callback_query:
        await update.callback_query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')

    return SELECTING_ACTION

async def back_to_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    return await start(update, context)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    if query:
        await query.answer()
        await query.edit_message_text("Opération annulée.")
    else:
        await update.message.reply_text("Opération annulée.")
    return await back_to_main_menu(update, context)

# --- HANDLERS POUR LES MODULES ---

async def ask_for_target(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    module = query.data
    context.user_data['module'] = module

    if module == 'exfil':
        return await confirm_action(update, context)

    await query.edit_message_text(
        f"🎯 *Module sélectionné : {module.upper()}*\n\nVeuillez entrer la cible (ex: `exemple.com` ou `192.168.1.1`):",
        parse_mode='Markdown'
    )
    return AWAITING_TARGET

async def handle_target_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['target'] = update.message.text
    module = context.user_data.get('module')

    if module == 'dos':
        await update.message.reply_text("🔢 Port à attaquer (ex: 80) :")
        return AWAITING_DOS_PORT
    elif module == 'bruteforce':
        keyboard = [
            [InlineKeyboardButton("SSH", callback_data='ssh'),
             InlineKeyboardButton("FTP", callback_data='ftp')],
            [InlineKeyboardButton("Telnet", callback_data='telnet'),
             InlineKeyboardButton("🌐 HTTP", callback_data='web')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("🔧 Quel service voulez-vous attaquer ?", reply_markup=reply_markup)
        return AWAITING_BRUTEFORCE_SERVICE

    return await confirm_action(update, context)

async def handle_dos_port_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['port'] = update.message.text
    await update.message.reply_text("⏱️ Durée de l'attaque en secondes (ex: 60) :")
    return AWAITING_DOS_DURATION

async def handle_dos_duration_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['duration'] = update.message.text
    return await confirm_action(update, context)

async def handle_bruteforce_service_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data['service'] = query.data
    await query.edit_message_text("👤 Entrez le chemin vers la liste d'utilisateurs (ex: data/usernames.txt) :")
    return AWAITING_BRUTEFORCE_USERLIST

async def handle_bruteforce_userlist_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['userlist'] = update.message.text
    await update.message.reply_text("🔑 Entrez le chemin vers la liste de mots de passe (ex: data/passwords.txt) :")
    return AWAITING_BRUTEFORCE_PASSLIST

async def handle_bruteforce_passlist_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['passlist'] = update.message.text
    return await confirm_action(update, context)

async def confirm_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    module = context.user_data.get('module')
    target = context.user_data.get('target', 'N/A')
    text = f"✅ *Prêt à lancer ?*\n\n  - *Module* : `{module.upper()}`\n  - *Cible* : `{target}`\n\nConfirmez-vous le lancement ?"

    keyboard = [
        [InlineKeyboardButton("✅ Oui, lancer", callback_data='confirm_yes'),
         InlineKeyboardButton("❌ Non, annuler", callback_data='confirm_no')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    if update.message:
        await update.message.reply_text(text, reply_markup=reply_markup, parse_mode='Markdown')
    elif update.callback_query:
        await update.callback_query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')

    return AWAITING_CONFIRMATION

async def run_module(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()

    module = context.user_data.get('module')
    target = context.user_data.get('target')
    chat_id = update.effective_chat.id

    await query.edit_message_text(f"🚀 *Lancement en cours...*\nModule : `{module.upper()}`\nCible : `{target or 'N/A'}`", parse_mode='Markdown')

    try:
        result = None
        if module == 'dos':
            port = int(context.user_data.get('port'))
            duration = int(context.user_data.get('duration'))
            use_tor = context.user_data.get('use_tor', False)

            await asyncio.to_thread(dos.start_attack, target, port, duration, use_tor)

            start_time = time.time()
            while (time.time() - start_time) < duration and dos.get_status()['running']:
                status = dos.get_status()
                text = f"💥 *Attaque DoS en cours...* 💥\n\n  - *Cible* : `{status['target']}`\n  - *Port* : `{status['port']}`\n  - *Paquets/s* : `{status['pps']}`\n  - *Échecs/s* : `{status['failed_pps']}`\n  - *Temps écoulé* : `{int(time.time() - start_time)}s / {duration}s`\n"
                try:
                    await query.edit_message_text(text, parse_mode='Markdown')
                except Exception:
                    pass
                await asyncio.sleep(2)
            
            if dos.get_status()['running']:
                await asyncio.to_thread(dos.stop_attack)
            result = f"Attaque DoS sur {target}:{port} terminée."
        else:
            def blocking_task():
                # Réinitialiser et créer un nouveau répertoire de session pour ce scan
                utils.reset_session_dir()
                session_dir = utils.get_current_session_dir()

                config = utils.load_config()
                use_tor = config.get('use_tor', False)

                if module in ['osint', 'web']:
                    session = utils.get_requests_session(force_tor=use_tor)
                    if module == 'osint':
                        osint.session = session
                    else:
                        exploit_web.session = session

                if module == 'osint':
                    osint.run(target, session_dir)
                elif module == 'scan':
                    scanner.run(target, session_dir, use_tor=use_tor)
                elif module == 'web':
                    exploit_web.run(target, session_dir)
                elif module == 'bruteforce':
                    service = context.user_data.get('service')
                    
                    service_to_port = {
                        'ssh': 22, 'ftp': 21, 'telnet': 23, 'mysql': 3306, 'postgres': 5432, 'web': 80
                    }
                    port = service_to_port.get(service)

                    options = {
                        'service': service,
                        'target': target,
                        'port': port,
                        'userlist': context.user_data.get('userlist'),
                        'passlist': context.user_data.get('passlist'),
                        'threads': 50,
                        'timeout': 5
                    }
                    bruteforce.run('dictionary', options)
                
                # Le rapport est généré à partir des fichiers dans la session active
                return reporting.run(target, session_dir)

            result = await asyncio.to_thread(blocking_task)

        if module != 'dos':
            txt_file, pdf_file, _ = result
            await query.edit_message_text("✅ Tâche terminée. Envoi des rapports...")
            
            if txt_file and os.path.exists(os.path.join('outputs', txt_file)):
                with open(os.path.join('outputs', txt_file), 'r', encoding='utf-8', errors='replace') as f:
                    preview = f.read(1000)
                await context.bot.send_message(chat_id=chat_id, text=f"📄 *Aperçu des résultats ({txt_file})*\n\n`{preview}`...", parse_mode='Markdown')

            for report_file in [txt_file, pdf_file]:
                if report_file and os.path.exists(os.path.join('outputs', report_file)):
                    with open(os.path.join('outputs', report_file), 'rb') as f:
                        await context.bot.send_document(chat_id=chat_id, document=f)
                else:
                    await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur : Fichier de rapport {report_file} non trouvé.")
        else:
             await query.edit_message_text(result)

    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur : {e}")
    
    return await back_to_main_menu(update, context)

# --- GESTION DE TOR ---
async def tor_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    config = utils.load_config()
    status = "✅ Activé" if config.get('use_tor') else "❌ Désactivé"
    keyboard = [
        [InlineKeyboardButton(f"Basculer TOR (actuel: {status})", callback_data='toggle_tor')],
        [InlineKeyboardButton("⬅️ Retour", callback_data='main_menu')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("🔒 *Menu de gestion TOR*", reply_markup=reply_markup, parse_mode='Markdown')
    return SELECTING_ACTION

async def toggle_tor(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    config = utils.load_config()
    config['use_tor'] = not config.get('use_tor', False)
    utils.save_config(config)
    await query.message.reply_text(f"TOR est maintenant {'activé' if config['use_tor'] else 'désactivé'}.")
    return await tor_menu(update, context)

# --- GESTION DE LA STÉGANOGRAPHIE ---

async def stegano_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    keyboard = [
        [InlineKeyboardButton(" caché un fichier", callback_data='stegano_hide'),
         InlineKeyboardButton("🤫 Révéler un fichier", callback_data='stegano_reveal')],
        [InlineKeyboardButton("⬅️ Retour", callback_data='main_menu')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("🖼️ *Menu Stéganographie*\n\nQue souhaitez-vous faire ?", reply_markup=reply_markup, parse_mode='Markdown')
    return SELECTING_STEGANO_ACTION

async def stegano_ask_for_cover_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data['stegano_state'] = AWAITING_STEGANO_IMAGE_HIDE
    await query.edit_message_text("‼️ *IMPORTANT* ‼️\n\nVeuillez envoyer l'image de couverture EN TANT QUE **FICHIER** (non compressé). N'utilisez PAS l'option 'Photo'.")
    return AWAITING_STEGANO_IMAGE_HIDE

async def stegano_ask_for_reveal_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data['stegano_state'] = AWAITING_STEGANO_IMAGE_REVEAL
    await query.edit_message_text("‼️ *IMPORTANT* ‼️\n\nVeuillez envoyer l'image contenant le secret EN TANT QUE **FICHIER** (non compressé). N'utilisez PAS l'option 'Photo'.")
    return AWAITING_STEGANO_IMAGE_REVEAL

async def stegano_handle_image_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    message = update.message
    state = context.user_data.get('stegano_state')
    keyboard_back = [[InlineKeyboardButton("⬅️ Retour au menu principal", callback_data='main_menu')]]
    reply_markup_back = InlineKeyboardMarkup(keyboard_back)

    if not message.document or not message.document.mime_type or not message.document.mime_type.startswith('image/') :
        await message.reply_text("❌ Erreur : Veuillez envoyer une image en tant que **Document**.", reply_markup=reply_markup_back, parse_mode='Markdown')
        return state

    file_to_process = message.document
    file_id = file_to_process.file_id
    file = await context.bot.get_file(file_id)
    
    outputs_dir = os.path.join(os.path.dirname(__file__), '..', 'outputs')
    os.makedirs(outputs_dir, exist_ok=True)
    
    temp_file_path = os.path.join(outputs_dir, file_to_process.file_name)
    await file.download_to_drive(temp_file_path)

    if state == AWAITING_STEGANO_IMAGE_HIDE:
        context.user_data['cover_image'] = temp_file_path
        await message.reply_text("✅ Image de couverture reçue. Envoyez maintenant le fichier secret (en tant que document).")
        return AWAITING_STEGANO_SECRET_FILE

    elif state == AWAITING_STEGANO_IMAGE_REVEAL:
        await message.reply_text("Image reçue. Traitement en cours...")
        
        output_filename = "revealed_secret.dat"
        output_path = os.path.join(outputs_dir, output_filename)

        result = await asyncio.to_thread(crypto_tools.stegano_reveal_file, temp_file_path, output_path)

        if "Succès" in result:
            await message.reply_text("Secret trouvé ! Voici le fichier extrait :")
            with open(output_path, 'rb') as f:
                await context.bot.send_document(chat_id=message.chat_id, document=f)
        else:
            await message.reply_text(f"Erreur ou secret non trouvé : {result}")

        if os.path.exists(temp_file_path): os.remove(temp_file_path)
        if os.path.exists(output_path): os.remove(output_path)
        await message.reply_text("Opération terminée.", reply_markup=reply_markup_back)
        context.user_data.clear()
        return ConversationHandler.END

async def stegano_handle_secret_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    message = update.message
    chat_id = message.chat_id
    keyboard_back = [[InlineKeyboardButton("⬅️ Retour au menu principal", callback_data='main_menu')]]
    reply_markup_back = InlineKeyboardMarkup(keyboard_back)

    if not message.document:
        await message.reply_text("❌ Erreur : Veuillez envoyer le secret en tant que **Document**.", reply_markup=reply_markup_back, parse_mode='Markdown')
        return AWAITING_STEGANO_SECRET_FILE

    secret_file_to_process = message.document
    file_id = secret_file_to_process.file_id
    file = await context.bot.get_file(file_id)
    
    outputs_dir = os.path.join(os.path.dirname(__file__), '..', 'outputs')
    os.makedirs(outputs_dir, exist_ok=True)
    
    secret_file_path = os.path.join(outputs_dir, secret_file_to_process.file_name)
    await file.download_to_drive(secret_file_path)

    cover_image_path = context.user_data.get('cover_image')
    
    if not cover_image_path:
        await message.reply_text("Erreur : l'image de couverture est manquante. Veuillez recommencer.", reply_markup=reply_markup_back)
        return await back_to_main_menu(update, context)

    await message.reply_text("Fichiers reçus. Traitement en cours...")
    
    output_filename = "stegano_" + os.path.basename(cover_image_path)
    output_path = os.path.join(outputs_dir, output_filename)

    result = await asyncio.to_thread(crypto_tools.stegano_hide_file, cover_image_path, secret_file_path, output_path)

    if "Succès" in result:
        await message.reply_text("Opération terminée. Voici votre image avec le fichier caché :")
        with open(output_path, 'rb') as f:
            await context.bot.send_document(chat_id=chat_id, document=f)
    else:
        await message.reply_text(f"Erreur lors du traitement : {result}")

    if os.path.exists(cover_image_path): os.remove(cover_image_path)
    if os.path.exists(secret_file_path): os.remove(secret_file_path)
    if os.path.exists(output_path): os.remove(output_path)
    await message.reply_text("Opération terminée.", reply_markup=reply_markup_back)
    context.user_data.clear()
    return ConversationHandler.END

# --- LANCEMENT PRINCIPAL ---

def run():
    TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    if not TOKEN or TOKEN == "VOTRE_TOKEN_DE_BOT_TELEGRAM":
        utils.log_message('-', "Le token du bot Telegram n'est pas configuré.")
        return

    utils.log_message('*', "Lancement du bot Telegram interactif...")
    app = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            SELECTING_ACTION: [
                CallbackQueryHandler(ask_for_target, pattern='^(osint|scan|web|report|exfil|dos|bruteforce)$'),
                CallbackQueryHandler(stegano_menu, pattern='^stegano$'),
                CallbackQueryHandler(tor_menu, pattern='^tor_menu$'),
                CallbackQueryHandler(toggle_tor, pattern='^toggle_tor$'),
                CallbackQueryHandler(back_to_main_menu, pattern='^main_menu$'),
            ],
            AWAITING_TARGET: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_target_input)
            ],
            AWAITING_CONFIRMATION: [
                CallbackQueryHandler(run_module, pattern='^confirm_yes$'),
                CallbackQueryHandler(cancel, pattern='^confirm_no$')
            ],
            AWAITING_DOS_PORT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_dos_port_input)
            ],
            AWAITING_DOS_DURATION: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_dos_duration_input)
            ],
            AWAITING_BRUTEFORCE_SERVICE: [
                CallbackQueryHandler(handle_bruteforce_service_input)
            ],
            AWAITING_BRUTEFORCE_USERLIST: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bruteforce_userlist_input)
            ],
            AWAITING_BRUTEFORCE_PASSLIST: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bruteforce_passlist_input)
            ],
            # Stegano states
            SELECTING_STEGANO_ACTION: [
                CallbackQueryHandler(stegano_ask_for_cover_image, pattern='^stegano_hide$'),
                CallbackQueryHandler(stegano_ask_for_reveal_image, pattern='^stegano_reveal$'),
            ],
            AWAITING_STEGANO_IMAGE_HIDE: [
                MessageHandler(filters.Document.IMAGE, stegano_handle_image_file)
            ],
            AWAITING_STEGANO_SECRET_FILE: [
                MessageHandler(filters.Document.ALL, stegano_handle_secret_file)
            ],
            AWAITING_STEGANO_IMAGE_REVEAL: [
                MessageHandler(filters.Document.IMAGE, stegano_handle_image_file)
            ],
        },
        fallbacks=[CommandHandler('cancel', cancel), CallbackQueryHandler(back_to_main_menu, pattern='^main_menu$')],
        per_message=False,
        allow_reentry=True
    )

    app.add_handler(conv_handler)
    app.add_handler(CommandHandler('start', start))
    app.run_polling()

if __name__ == '__main__':
    # Correction pour l'exécution directe du bot
    if os.path.basename(os.getcwd()) == 'modules':
        os.chdir('..')
        sys.path.insert(0, os.getcwd())
    from modules import utils
    run()
