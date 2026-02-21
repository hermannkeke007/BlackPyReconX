# BlackPyReconX - Un framework d'attaque complet
# Copyright (C) 2025 Hermann KEKE
#
# Ce programme est un logiciel libre ; vous pouvez le redistribuer et/ou le
# modifier selon les termes de la Licence publique générale GNU telle que
# publiée par la Free Software Foundation ; soit la version 3 de la Licence,
# soit (à votre choix) toute version ultérieure.
#
# Ce programme est distribué dans l'espoir qu'il sera utile,
# mais SANS AUCUNE GARANTIE ; sans même la garantie implicite de
# QUALITÉ MARCHANDE ou d'ADÉQUATION À UN USAGE PARTICULIER. Voir la
# Licence publique générale GNU pour plus de détails.
#
# Vous devriez avoir reçu une copie de la Licence publique générale GNU
# avec ce programme. Si non, voir <https://www.gnu.org/licenses/>.

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
AWAITING_STEGANO_SECRET_FILE, AWAITING_STEGANO_IMAGE_REVEAL,
TOR_MENU_STATE, POST_TASK_MENU) = range(25)

# --- MENUS ET HANDLERS DE BASE ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    keyboard = [
        [InlineKeyboardButton("🔍 OSINT", callback_data='osint'),
         InlineKeyboardButton("📡 Scan de Ports", callback_data='scan')],
        [InlineKeyboardButton("🌐 Scan Web", callback_data='web'),
         InlineKeyboardButton("📄 Rapport", callback_data='report')],
        [InlineKeyboardButton("📍 Géolocalisation", callback_data='geo'), # New Geolocation button
         InlineKeyboardButton("📦 Exfiltration", callback_data='exfil'),
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

async def post_task_menu(update: Update, context: ContextTypes.DEFAULT_TYPE, message_text: str = "Tâche terminée.") -> int:
    keyboard = [[InlineKeyboardButton("⬅️ Retour au menu principal", callback_data='main_menu')]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Déterminer la méthode de réponse (message ou callback_query)
    if update.callback_query:
        # Essayer de modifier le message existant si possible
        try:
            await update.callback_query.edit_message_text(message_text, reply_markup=reply_markup, parse_mode='Markdown')
        except Exception: # Si le message est trop ancien ou déjà modifié
            await context.bot.send_message(chat_id=update.effective_chat.id, text=message_text, reply_markup=reply_markup, parse_mode='Markdown')
    elif update.message: # Si la conversation a été initiée par un message
        await update.message.reply_text(message_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    context.user_data.clear() # Clear user data after task
    return POST_TASK_MENU

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
    elif module == 'geo':
        await query.edit_message_text(
            f"🎯 *Module sélectionné : Géolocalisation*\n\nVeuillez entrer la cible (adresse IP ou domaine, ex: `google.com` ou `8.8.8.8`):",
            parse_mode='Markdown'
        )
        return AWAITING_TARGET

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
        if module == 'geo':
            # Similar to other report-generating modules
            def blocking_task_geo():
                utils.reset_session_dir()
                session_dir = utils.get_current_session_dir()
                osint.session = utils.get_requests_session(force_tor=False) # Geo module does not use TOR by default unless specified
                osint.run(target, session_dir, geo_flag=True) # Ensure raw geo data is saved
                return reporting.run(target, session_dir)

            txt_file, pdf_file, _ = await asyncio.to_thread(blocking_task_geo)
            
            await query.edit_message_text("✅ Géolocalisation terminée. Envoi des rapports...")
            
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
            
            return await post_task_menu(update, context, f"✅ Géolocalisation pour {target} terminée. Vos rapports sont joints.")
        elif module == 'dos':
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
            
            return await post_task_menu(update, context, f"✅ Tâche '{module.upper()}' terminée. Vos rapports sont joints.")
        else:
            await query.edit_message_text(result)
            return await post_task_menu(update, context, result)

    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur : {e}")
        return await post_task_menu(update, context, f"❌ Erreur lors de l'exécution du module. Détails: {e}")

# --- GESTION DE TOR ---
async def tor_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
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
    return TOR_MENU_STATE

async def toggle_tor(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    config = utils.load_config()
    config['use_tor'] = not config.get('use_tor', False)
    utils.save_config(config)
    await query.message.reply_text(f"TOR est maintenant {'activé' if config['use_tor'] else 'désactivé'}.")
    # After toggling, return to the TOR menu state to update the status display
    return await tor_menu(update, context)



# --- STÉGANOGRAPHIE ---
async def stegano_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    keyboard = [
        [InlineKeyboardButton("Cacher un fichier", callback_data='stegano_hide'),
         InlineKeyboardButton("Révéler un fichier", callback_data='stegano_reveal')],
        [InlineKeyboardButton("⬅️ Retour", callback_data='main_menu')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("🖼️ *Menu de Stéganographie*\n\nChoisissez une action :", reply_markup=reply_markup, parse_mode='Markdown')
    return SELECTING_STEGANO_ACTION

async def stegano_ask_for_cover_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data['stegano_action'] = 'hide'
    await query.edit_message_text("🖼️ Veuillez envoyer l'image de couverture (en tant que fichier/document).")
    return AWAITING_STEGANO_IMAGE_HIDE

async def stegano_ask_for_reveal_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data['stegano_action'] = 'reveal'
    await query.edit_message_text("🖼️ Veuillez envoyer l'image contenant le secret (en tant que fichier/document).")
    return AWAITING_STEGANO_IMAGE_REVEAL

async def stegano_handle_image_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.effective_chat.id
    action = context.user_data.get('stegano_action')

    try:
        doc = update.message.document
        if not doc.mime_type.startswith('image/'):
            await update.message.reply_text("❌ Erreur : Le fichier envoyé n'est pas une image.")
            return

        file = await context.bot.get_file(doc.file_id)
        
        # We need a predictable place to save files
        temp_dir = os.path.join(utils.get_current_session_dir(create=True), 'stegano_temp')
        os.makedirs(temp_dir, exist_ok=True)
        
        file_path = os.path.join(temp_dir, doc.file_name)
        await file.download_to_drive(file_path)

        context.user_data['image_path'] = file_path
        await update.message.reply_text(f"✅ Image '{doc.file_name}' reçue.")

        if action == 'hide':
            await update.message.reply_text("📂 Maintenant, envoyez le fichier secret à cacher.")
            return AWAITING_STEGANO_SECRET_FILE
        elif action == 'reveal':
            return await stegano_run_reveal(update, context)

    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur lors de la gestion de l'image : {e}")
        return await back_to_main_menu(update, context)


async def stegano_handle_secret_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.effective_chat.id

    try:
        doc = update.message.document
        file = await context.bot.get_file(doc.file_id)
        
        temp_dir = os.path.join(utils.get_current_session_dir(), 'stegano_temp')
        secret_path = os.path.join(temp_dir, doc.file_name)
        await file.download_to_drive(secret_path)

        context.user_data['secret_path'] = secret_path
        await update.message.reply_text(f"✅ Fichier secret '{doc.file_name}' reçu.")
        
        return await stegano_run_hide(update, context)

    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur lors de la gestion du fichier secret : {e}")
        return await back_to_main_menu(update, context)


async def stegano_run_hide(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    image_path = context.user_data.get('image_path')
    secret_path = context.user_data.get('secret_path')

    if not all([image_path, secret_path]):
        await update.message.reply_text("❌ Erreur : L'image de couverture ou le fichier secret est manquant.")
        return await back_to_main_menu(update, context)

    await update.message.reply_text("⏳ Dissimulation du fichier en cours...")
    
    try:
        output_filename = f"steg_{os.path.basename(image_path)}"
        output_path = os.path.join(os.path.dirname(image_path), output_filename)

        def blocking_task():
            return crypto_tools.stegano_hide_file(image_path, secret_path, output_path)
            
        result = await asyncio.to_thread(blocking_task)

        if "Succès" in result:
            await update.message.reply_text("✅ Fichier caché avec succès ! Envoi de l'image modifiée...")
            with open(output_path, 'rb') as f:
                await context.bot.send_document(chat_id=chat_id, document=f, filename=output_filename)
        else:
            await update.message.reply_text(f"❌ Échec de la dissimulation du fichier. Raison : {result}")

    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur lors de la stéganographie : {e}")
        
    return await back_to_main_menu(update, context)

async def stegano_run_reveal(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    image_path = context.user_data.get('image_path')

    if not image_path:
        await update.message.reply_text("❌ Erreur : L'image à analyser est manquante.")
        return await back_to_main_menu(update, context)

    await update.message.reply_text("🔎 Recherche d'un fichier caché en cours...")

    try:
        output_filename = "revealed_secret.txt" # Default name
        output_path = os.path.join(os.path.dirname(image_path), output_filename)

        def blocking_task():
            return crypto_tools.stegano_reveal_file(image_path, output_path)

        result = await asyncio.to_thread(blocking_task)

        if "Succès" in result:
            await update.message.reply_text("✅ Fichier caché trouvé et extrait ! Envoi du fichier...")
            with open(output_path, 'rb') as f:
                await context.bot.send_document(chat_id=chat_id, document=f, filename=os.path.basename(output_path))
        else:
            await update.message.reply_text(f"AUCUN fichier caché n'a été trouvé ou une erreur est survenue. Raison : {result}")

    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur lors de la révélation : {e}")

    return await back_to_main_menu(update, context)

# --- LANCEMENT PRINCIPAL ---

def run():
    config = utils.load_config()
    TOKEN = utils.get_api_key("telegram_bot_token")
    if not TOKEN:
        utils.log_message('-', "Le token du bot Telegram n'est pas configuré dans config.json.")
        return

    utils.log_message('*', "Lancement du bot Telegram interactif...")
    app = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            SELECTING_ACTION: [
                CallbackQueryHandler(ask_for_target, pattern='^(osint|scan|web|report|exfil|dos|bruteforce|geo)$'),
                CallbackQueryHandler(stegano_menu, pattern='^stegano$'),
                CallbackQueryHandler(tor_menu, pattern='^tor_menu$'),
            ],
            TOR_MENU_STATE: [
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
            SELECTING_STEGANO_ACTION: [
                CallbackQueryHandler(stegano_ask_for_cover_image, pattern='^stegano_hide$'),
                CallbackQueryHandler(stegano_ask_for_reveal_image, pattern='^stegano_reveal$'),
                CallbackQueryHandler(back_to_main_menu, pattern='^main_menu$'),
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
            POST_TASK_MENU: [
                CallbackQueryHandler(back_to_main_menu, pattern='^main_menu$'),
            ]
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
    run()