import os
import sys
import json
import asyncio

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

from modules import osint, scanner, exploit_web, reporting, exfiltration, utils

# États pour la conversation
SELECTING_ACTION, AWAITING_TARGET, AWAITING_CONFIRMATION = range(3)

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
        [InlineKeyboardButton("📦 Exfiltration", callback_data='exfil')],
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
    return await confirm_action(update, context)

# Confirmation avant lancement
async def confirm_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    module = context.user_data.get('module')
    target = context.user_data.get('target', 'N/A')

    if module == 'exfil':
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

    await query.edit_message_text(f"""🚀 *Lancement en cours...*\nModule : `{module.upper()}`\nCible : `{target or 'N/A'}`\n\nVeuillez patienter, cela peut prendre du temps.""", parse_mode='Markdown')

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
        return None

    try:
        result = await asyncio.to_thread(blocking_task)

        if module == 'report' and result:
            _, txt_file, pdf_file, html_file = result
            for fname in [txt_file, pdf_file, html_file]:
                if fname and os.path.exists(os.path.join('outputs', fname)):
                    with open(os.path.join('outputs', fname), 'rb') as f:
                        await context.bot.send_document(chat_id=chat_id, document=f)

        elif module == 'exfil':
            key_path = os.path.join('outputs', 'encryption_key.key')
            archive = next((os.path.join('outputs', f) for f in sorted(os.listdir('outputs'), reverse=True) if f.endswith('.zip.enc')), None)
            if archive and os.path.exists(key_path):
                for fpath in [archive, key_path]:
                    with open(fpath, 'rb') as f:
                        await context.bot.send_document(chat_id=chat_id, document=f)
            else:
                await context.bot.send_message(chat_id=chat_id, text="❌ Fichiers d'exfiltration non trouvés.")

        elif result:
            result_path = os.path.join('outputs', result)
            if os.path.exists(result_path):
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
                    txt_report, pdf_report, html_report = await asyncio.to_thread(reporting.run, target)
                    if pdf_report and os.path.exists(os.path.join('outputs', pdf_report)):
                        with open(os.path.join('outputs', pdf_report), 'rb') as f_pdf:
                            await context.bot.send_document(chat_id=chat_id, document=f_pdf)
                except Exception as pdf_error:
                    await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur PDF : `{str(pdf_error)}`", parse_mode='Markdown')

        else:
            await context.bot.send_message(chat_id=chat_id, text=f"❌ Aucun résultat exploitable trouvé.")

    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"❌ Erreur lors de l'exécution : `{str(e)}`", parse_mode='Markdown')
    finally:
        context.user_data.clear()
        return await start(update, context)

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
                CallbackQueryHandler(ask_for_target, pattern='^(osint|scan|web|report|exfil)$'),
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