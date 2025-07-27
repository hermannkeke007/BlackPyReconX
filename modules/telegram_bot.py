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

from modules import osint, scanner, exploit_web, reporting, exfiltration, utils, dos, bruteforce

# États pour la conversation
SELECTING_ACTION, AWAITING_TARGET, AWAITING_CONFIRMATION, AWAITING_DOS_PORT, AWAITING_DOS_DURATION, AWAITING_BRUTEFORCE_SERVICE, AWAITING_BRUTEFORCE_USERLIST, AWAITING_BRUTEFORCE_PASSLIST, AWAITING_DOS_TOR, AWAITING_STOP, AWAITING_BRUTEFORCE_TYPE, AWAITING_BRUTEFORCE_USERNAME, AWAITING_BRUTEFORCE_CHARSET, AWAITING_BRUTEFORCE_MIN_LEN, AWAITING_BRUTEFORCE_MAX_LEN, AWAITING_BRUTEFORCE_URL, AWAITING_BRUTEFORCE_USER_FIELD, AWAITING_BRUTEFORCE_PASS_FIELD, AWAITING_BRUTEFORCE_FAIL_STRING = range(19)

# Config globale
def load_config():
    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'config.json'), 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_config(config_data):
    with open(os.path.join(os.path.dirname(__file__), '..', 'config.json'), 'w') as f:
        json.dump(config_data, f, indent=4)

# Menu principal
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    keyboard = [
        [InlineKeyboardButton("🔍 OSINT", callback_data='osint'),
         InlineKeyboardButton("📡 Scan de Ports", callback_data='scan')],
        [InlineKeyboardButton("🌐 Scan Web", callback_data='web'),
         InlineKeyboardButton("📄 Rapport", callback_data='report')],
        [InlineKeyboardButton("📦 Exfiltration", callback_data='exfil'),
         InlineKeyboardButton("💥 Attaque DoS", callback_data='dos'),
         InlineKeyboardButton("💪 Force Brute", callback_data='bruteforce')],
        [InlineKeyboardButton("🔒 Gérer TOR", callback_data='tor_menu')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    text = "🤖 *Bienvenue sur le bot de contrôle BlackPyReconX*\n\nChoisissez une action à exécuter :"

    if update.message:
        await update.message.reply_text(text, reply_markup=reply_markup, parse_mode='Markdown')
    elif update.callback_query:
        await update.callback_query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')

    return SELECTING_ACTION

# Sélection de cible
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
    keyboard = [
        [InlineKeyboardButton("✅ Oui", callback_data='dos_tor_yes'),
         InlineKeyboardButton("❌ Non", callback_data='dos_tor_no')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("🔒 Voulez-vous utiliser TOR pour cette attaque ?", reply_markup=reply_markup)
    return AWAITING_DOS_TOR

async def handle_dos_tor_choice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data['use_tor'] = query.data == 'dos_tor_yes'
    return await confirm_action(update, context)

async def handle_bruteforce_service_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data['service'] = query.data
    keyboard = [
        [InlineKeyboardButton("📖 Dictionnaire", callback_data='dictionary')],
        [InlineKeyboardButton("⚙️ Force Brute Pure", callback_data='bruteforce')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("⚔️ Choisissez le type d'attaque :", reply_markup=reply_markup)
    return AWAITING_BRUTEFORCE_TYPE

async def handle_bruteforce_userlist_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['userlist'] = update.message.text
    await update.message.reply_text("🔑 Entrez le chemin vers la liste de mots de passe (ex: data/passwords.txt) :")
    return AWAITING_BRUTEFORCE_PASSLIST

async def handle_bruteforce_type_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data['attack_type'] = query.data

    if context.user_data.get('service') == 'web':
        await query.edit_message_text("🌐 Entrez l'URL de la page de connexion :")
        return AWAITING_BRUTEFORCE_URL

    if query.data == 'dictionary':
        await query.edit_message_text("👤 Entrez le chemin vers la liste d'utilisateurs (ex: data/usernames.txt) :")
        return AWAITING_BRUTEFORCE_USERLIST
    else:
        await query.edit_message_text("👤 Entrez le nom d'utilisateur unique à cibler :")
        return AWAITING_BRUTEFORCE_USERNAME

async def handle_bruteforce_url_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['url'] = update.message.text
    await update.message.reply_text("👤 Entrez le nom du champ utilisateur :")
    return AWAITING_BRUTEFORCE_USER_FIELD

async def handle_bruteforce_user_field_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['user_field'] = update.message.text
    await update.message.reply_text("🔑 Entrez le nom du champ mot de passe :")
    return AWAITING_BRUTEFORCE_PASS_FIELD

async def handle_bruteforce_pass_field_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['pass_field'] = update.message.text
    await update.message.reply_text("❌ Entrez la chaîne de caractères indiquant un échec de connexion :")
    return AWAITING_BRUTEFORCE_FAIL_STRING

async def handle_bruteforce_fail_string_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['fail_string'] = update.message.text
    if context.user_data.get('attack_type') == 'dictionary':
        await update.message.reply_text("👤 Entrez le chemin vers la liste d'utilisateurs (ex: data/usernames.txt) :")
        return AWAITING_BRUTEFORCE_USERLIST
    else:
        await update.message.reply_text("👤 Entrez le nom d'utilisateur unique à cibler :")
        return AWAITING_BRUTEFORCE_USERNAME

async def handle_bruteforce_username_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['username'] = update.message.text
    keyboard = [
        [InlineKeyboardButton("Alphanumérique", callback_data='alphanum'),
         InlineKeyboardButton("Numérique", callback_data='digits')],
        [InlineKeyboardButton("Minuscules", callback_data='lower'),
         InlineKeyboardButton("Majuscules", callback_data='upper')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("🔠 Choisissez le jeu de caractères :", reply_markup=reply_markup)
    return AWAITING_BRUTEFORCE_CHARSET

async def handle_bruteforce_charset_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data['charset'] = query.data
    await query.edit_message_text("🔢 Entrez la longueur minimale du mot de passe :")
    return AWAITING_BRUTEFORCE_MIN_LEN

async def handle_bruteforce_min_len_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['min_len'] = update.message.text
    await update.message.reply_text("🔢 Entrez la longueur maximale du mot de passe :")
    return AWAITING_BRUTEFORCE_MAX_LEN

async def handle_bruteforce_max_len_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['max_len'] = update.message.text
    return await confirm_action(update, context)

async def handle_bruteforce_passlist_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['passlist'] = update.message.text
    return await confirm_action(update, context)

async def stop_task(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    module = context.user_data.get('module')

    if module == 'dos':
        dos.stop_attack()
    elif module == 'scan':
        scanner.stop_scan()
    elif module == 'bruteforce':
        bruteforce.stop_bruteforce()
    
    await query.edit_message_text("🛑 Ordre d'arrêt envoyé.")
    return SELECTING_ACTION

# Confirmation avant lancement
async def confirm_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    module = context.user_data.get('module')
    target = context.user_data.get('target', 'N/A')

    if module == 'dos':
        port = context.user_data.get('port')
        duration = context.user_data.get('duration')
        use_tor = context.user_data.get('use_tor', False)
        tor_ip_message = ""
        if use_tor:
            try:
                session = utils.get_requests_session(force_tor=True)
                ip = session.get("https://httpbin.org/ip").json()['origin']
                tor_ip_message = f"\n  - *IP Tor* : `{ip}`"
            except Exception as e:
                tor_ip_message = f"\n  - *IP Tor* : `Erreur - {e}`"

        text = f"""⚠️ *CONFIRMATION REQUISE* ⚠️\n\nVous êtes sur le point de lancer une attaque DoS.\n\n  - *Module* : `{module.upper()}`\n  - *Cible* : `{target}`\n  - *Port* : `{port}`\n  - *Durée* : `{duration} secondes`{tor_ip_message}\n\n*Assurez-vous d'avoir une autorisation explicite.*\nConfirmez-vous le lancement ?"""
    elif module == 'bruteforce':
        attack_type = context.user_data.get('attack_type')
        service = context.user_data.get('service')
        details = ""
        if attack_type == 'dictionary':
            userlist = context.user_data.get('userlist')
            passlist = context.user_data.get('passlist')
            details = f"\n  - *Userlist* : `{userlist}`\n  - *Passlist* : `{passlist}`"
        else:
            username = context.user_data.get('username')
            charset = context.user_data.get('charset')
            min_len = context.user_data.get('min_len')
            max_len = context.user_data.get('max_len')
            details = f"\n  - *Username* : `{username}`\n  - *Charset* : `{charset}`\n  - *Min Length* : `{min_len}`\n  - *Max Length* : `{max_len}`"
        if service == 'web':
            url = context.user_data.get('url')
            user_field = context.user_data.get('user_field')
            pass_field = context.user_data.get('pass_field')
            fail_string = context.user_data.get('fail_string')
            details += f"\n  - *URL* : `{url}`\n  - *User Field* : `{user_field}`\n  - *Pass Field* : `{pass_field}`\n  - *Fail String* : `{fail_string}`"

        text = f"""✅ *Prêt à lancer ?*\n\n  - *Module* : `{module.upper()}`\n  - *Cible* : `{target}`\n  - *Service* : `{service}`\n  - *Type* : `{attack_type.capitalize()}`{details}\n\nConfirmez-vous le lancement ?"""
    elif module == 'exfil':
        text = """📦 *Module : Exfiltration*\n\nCette action va compresser et chiffrer tous les fichiers de résultats dans le dossier `outputs`.\n\nÊtes-vous sûr de vouloir continuer ?"""
    else:
        text = f"""✅ *Prêt à lancer ?*\n\n  - *Module* : `{module.upper()}`\n  - *Cible* : `{target}`\n\nConfirmez-vous le lancement ?"""

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

    keyboard = [[InlineKeyboardButton("🛑 Arrêter l'opération", callback_data='stop_task')]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text(f"""🚀 *Lancement en cours...*\nModule : `{module.upper()}`\nCible : `{target or 'N/A'}`\n\nVeuillez patienter, cela peut prendre du temps.""", reply_markup=reply_markup, parse_mode='Markdown')

    keyboard_back = [[InlineKeyboardButton("⬅️ Retour au menu principal", callback_data='main_menu')]]
    reply_markup_back = InlineKeyboardMarkup(keyboard_back)

    try:
        # S'assurer que le dossier de sortie existe
        os.makedirs(os.path.join(os.path.dirname(__file__), '..', 'outputs'), exist_ok=True)

        if module == 'dos':
            port = context.user_data.get('port')
            duration = int(context.user_data.get('duration'))
            use_tor = context.user_data.get('use_tor', False)

            await asyncio.to_thread(dos.start_attack, target, port, duration, use_tor)

            start_time = time.time()
            while (time.time() - start_time) < duration and dos.get_status()['running']:
                status = dos.get_status()
                text = f"""💥 *Attaque DoS en cours...* 💥\n\n  - *Cible* : `{status['target']}`\n  - *Port* : `{status['port']}`\n  - *Paquets/s* : `{status['pps']}`\n  - *Échecs/s* : `{status['failed_pps']}`\n  - *Temps écoulé* : `{int(time.time() - start_time)}s / {duration}s`\n"""
                try:
                    await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
                except Exception:
                    pass
                await asyncio.sleep(2)
            
            if dos.get_status()['running']:
                await asyncio.to_thread(dos.stop_attack)
            result = f"Attaque DoS sur {target}:{port} terminée."
        else:
            def blocking_task():
                config = utils.load_config()
                use_tor = config.get('use_tor', False)

                if module == 'report':
                    return reporting.run(target)
                elif module == 'exfil':
                    exfiltration.run()
                    return None
                elif module == 'osint':
                    osint.session = utils.get_requests_session(force_tor=use_tor)
                    osint.run(target)
                    return 'osint.txt'
                elif module == 'scan':
                    scanner.run(target, use_tor=use_tor)
                    return 'scan_results.txt'
                elif module == 'web':
                    exploit_web.session = utils.get_requests_session(force_tor=use_tor)
                    exploit_web.run(target)
                    return 'web_vulns.txt'
                elif module == 'bruteforce':
                    attack_type = context.user_data.get('attack_type')
                    options = {
                        'service': context.user_data.get('service'),
                        'target': target,
                        'port': 22, # Default SSH port, will be updated later
                    }
                    if attack_type == 'dictionary':
                        options.update({
                            'userlist': context.user_data.get('userlist'),
                            'passlist': context.user_data.get('passlist'),
                        })
                    else:
                        options.update({
                            'username': context.user_data.get('username'),
                            'charset': context.user_data.get('charset'),
                            'min_len': int(context.user_data.get('min_len')),
                            'max_len': int(context.user_data.get('max_len')),
                        })
                    if options['service'] == 'web':
                        options.update({
                            'url': context.user_data.get('url'),
                            'user_field': context.user_data.get('user_field'),
                            'pass_field': context.user_data.get('pass_field'),
                            'fail_string': context.user_data.get('fail_string'),
                        })
                    bruteforce.run(attack_type, options)
                    return f"Attaque par force brute sur {target} terminée."
                return None
            result = await asyncio.to_thread(blocking_task)

        if module == 'report' and result:
            txt_file, pdf_file, html_file = result
            await query.edit_message_text("✅ Tâche terminée. Envoi des rapports...")
            for fname in [txt_file, pdf_file, html_file]:
                if fname and os.path.exists(os.path.join('outputs', fname)):
                    with open(os.path.join('outputs', fname), 'rb') as f:
                        await context.bot.send_document(chat_id=chat_id, document=f)

        elif module == 'exfil':
            await query.edit_message_text("✅ Tâche terminée. Envoi de l'archive chiffrée et de la clé...")
            key_path = os.path.join('outputs', 'encryption_key.key')
            archive = next((os.path.join('outputs', f) for f in sorted(os.listdir('outputs'), reverse=True) if f.endswith('.zip.enc')), None)
            if archive and os.path.exists(key_path):
                for fpath in [archive, key_path]:
                    with open(fpath, 'rb') as f:
                        await context.bot.send_document(chat_id=chat_id, document=f)
            else:
                await context.bot.send_message(chat_id=chat_id, text="❌ Fichiers d'exfiltration non trouvés.")

        elif result:
            if isinstance(result, str) and (result.startswith('Attaque') or result.startswith('Scan')):
                await query.edit_message_text(result)
            else:
                result_path = os.path.join('outputs', result)
                if os.path.exists(result_path):
                    await query.edit_message_text("✅ Tâche terminée. Envoi des résultats...")
                    with open(result_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    preview = content[:3500]
                    message = f"""📄 *Résultats pour {module.upper()}*\n\n```\n{preview}\n```"""
                    if len(content) > 3500:
                        message += "\n(résultats tronqués)"
                    await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')

                    with open(result_path, 'rb') as f:
                        await context.bot.send_document(chat_id=chat_id, document=f)

                    await context.bot.send_message(chat_id=chat_id, text="📄 Génération du rapport PDF...")
                    try:
                        _, pdf_report, _ = await asyncio.to_thread(reporting.run, target)
                        if pdf_report and os.path.exists(os.path.join('outputs', pdf_report)):
                            with open(os.path.join('outputs', pdf_report), 'rb') as f_pdf:
                                await context.bot.send_document(chat_id=chat_id, document=f_pdf)
                    except Exception as pdf_error:
                        await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur lors de la génération du PDF : `{str(pdf_error)}`", parse_mode='Markdown')

        else:
            await query.edit_message_text("✅ Tâche terminée, mais aucun résultat exploitable n'a été trouvé.")
        
        await context.bot.send_message(chat_id=chat_id, text="Vous pouvez maintenant retourner au menu.", reply_markup=reply_markup_back)

    except requests.exceptions.ProxyError as e:
        error_message = "❌ Erreur de proxy TOR. Le service est-il bien lancé sur le port 9150 ?"
        utils.log_message('-', f"[BOT ERROR] {error_message} - {e}")
        await query.edit_message_text(error_message, reply_markup=reply_markup_back)
    except requests.exceptions.ConnectionError as e:
        error_message = f"❌ Erreur de connexion. Impossible d'atteindre la cible `{target}`. Est-elle en ligne ?"
        utils.log_message('-', f"[BOT ERROR] {error_message} - {e}")
        await query.edit_message_text(error_message, parse_mode='Markdown', reply_markup=reply_markup_back)
    except socket.gaierror:
        error_message = f"❌ Erreur : Le nom d'hôte `{target}` est introuvable. Vérifiez l'orthographe."
        utils.log_message('-', f"[BOT ERROR] {error_message}")
        await query.edit_message_text(error_message, parse_mode='Markdown', reply_markup=reply_markup_back)
    except Exception as e:
        error_message = f"❌ Une erreur inattendue est survenue lors de l'exécution du module `{module}`."
        utils.log_message('-', f"[BOT ERROR] {error_message} - {e}")
        await query.edit_message_text(f"{error_message}\nConsultez les logs du serveur pour les détails.", parse_mode='Markdown', reply_markup=reply_markup_back)
    finally:
        context.user_data.clear()
        return SELECTING_ACTION

# --- GESTION DE TOR ---
async def tor_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    config = load_config()
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
    config = load_config()
    config['use_tor'] = not config.get('use_tor', False)
    save_config(config)
    await query.message.reply_text(f"TOR est maintenant {'activé' if config['use_tor'] else 'désactivé'}.")
    return await tor_menu(update, context)

# --- RETOUR & ANNULATION ---
async def back_to_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    return await start(update, context)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    if query:
        await query.answer()
        await query.edit_message_text("Opération annulée.")
    else:
        await update.message.reply_text("Opération annulée.")
    context.user_data.clear()
    return await start(update, context)

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
                CallbackQueryHandler(tor_menu, pattern='^tor_menu$'),
                CallbackQueryHandler(toggle_tor, pattern='^toggle_tor$'),
                CallbackQueryHandler(back_to_main_menu, pattern='^main_menu$'),
            ],
            AWAITING_TARGET: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_target_input)
            ],
            AWAITING_DOS_PORT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_dos_port_input)
            ],
            AWAITING_DOS_DURATION: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_dos_duration_input)
            ],
            AWAITING_DOS_TOR: [
                CallbackQueryHandler(handle_dos_tor_choice)
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
            AWAITING_BRUTEFORCE_TYPE: [
                CallbackQueryHandler(handle_bruteforce_type_input)
            ],
            AWAITING_BRUTEFORCE_USERNAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bruteforce_username_input)
            ],
            AWAITING_BRUTEFORCE_CHARSET: [
                CallbackQueryHandler(handle_bruteforce_charset_input)
            ],
            AWAITING_BRUTEFORCE_MIN_LEN: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bruteforce_min_len_input)
            ],
            AWAITING_BRUTEFORCE_MAX_LEN: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bruteforce_max_len_input)
            ],
            AWAITING_BRUTEFORCE_URL: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bruteforce_url_input)
            ],
            AWAITING_BRUTEFORCE_USER_FIELD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bruteforce_user_field_input)
            ],
            AWAITING_BRUTEFORCE_PASS_FIELD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bruteforce_pass_field_input)
            ],
            AWAITING_BRUTEFORCE_FAIL_STRING: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bruteforce_fail_string_input)
            ],
            AWAITING_CONFIRMATION: [
                CallbackQueryHandler(run_module, pattern='^confirm_yes$'),
                CallbackQueryHandler(cancel, pattern='^confirm_no$')
            ],
            AWAITING_STOP: [
                CallbackQueryHandler(stop_task, pattern='^stop_task$')
            ],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
        per_message=False,
        allow_reentry=True
    )

    app.add_handler(conv_handler)
    app.add_handler(CommandHandler('start', start))
    app.run_polling()

if __name__ == '__main__':
    run()
