# Discord Anti-Crypto Scam Bot

A Discord moderation bot that detects suspicious text, known scam domains, and scam images. When it finds a match, it deletes the message, bans or kicks the member, and posts the outcome to a configured log channel. Members with **Manage Messages** permission and administrators are exempt from automatic moderation.

## Detection

| Signal | How it works |
| --- | --- |
| Scam phrases | Case-insensitive matching against `scam_keywords` in message text and image OCR text. |
| Scam domains | Matches configured domains and their subdomains in HTTP(S) links. |
| Prohibited language | Matches `bad_words` as whole words or phrases. |
| Known scam images | Perceptual hash catches exact and near-duplicate images. |
| Similar scam images | Optional CLIP image embeddings compare attachments with learned examples. |
| Text inside images | Tesseract OCR checks image text against the same text rules. |

Only image attachments at or below `max_image_size_mb` are analyzed. The image formats used for training are PNG, JPEG, and WebP. Image similarity is based on the examples you supply; it is not a general scam classifier. Review new examples and moderation logs for false positives.

## Quick start with Docker

1. Create a bot in the [Discord Developer Portal](https://discord.com/developers/applications). Enable **Message Content Intent** and **Server Members Intent** on the Bot page.
2. Invite it with **Ban Members** (or **Kick Members** when using `action: kick`), **Manage Messages**, **Read Message History**, **View Channels**, and **Send Messages**. Place its role above members it must moderate.
3. Copy `.env.example` to `.env` and replace the placeholder with your bot token. Keep `.env` private.
4. Edit `config.yaml`: set `log_channel_id` to your moderation log channel and fill the keyword, domain, and prohibited-word lists for your server. Domain entries should be hostnames such as `example.com`, without a URL scheme.
5. Run `docker compose up -d --build` in this directory. Check output with `docker logs -f ycangignacy-scam-bot`.

The first CLIP run downloads its model. Docker keeps the model cache in a named volume. Set `learning.enable_ai_layer: false` to run hash matching and OCR without CLIP.

To run without Docker, use Python 3.11 or newer, install Tesseract OCR, install `requirements.txt`, and run `python bot.py`.

## Moderator commands

All commands require **Manage Messages** in the channel where they are used.

| Command | Purpose |
| --- | --- |
| `!learnscam` | Attach a scam image to the command, or reply to a message with an image, to learn it immediately. |
| `!listscams` | Show the 20 most recent learned examples with their IDs and sources. |
| `!unlearnscam <id>` | Remove an example from the database. |
| `!testword <text>` | Test text against the configured rules without a moderation action. |

You can also place `.png`, `.jpg`, `.jpeg`, or `.webp` files in `training_data/scam_examples/`. The bot imports them at startup. If you remove a folder-trained example with `!unlearnscam`, remove its original file too, or the bot will import it again at the next restart.

## Configuration

| Setting | Meaning |
| --- | --- |
| `log_channel_id` | Discord channel ID for moderation results. A value of `0` disables Discord logging. |
| `scam_keywords`, `scam_domains`, `bad_words` | Rules for text and OCR results. Empty lists match nothing. |
| `learning.enable_ai_layer` | Enable CLIP similarity matching. |
| `learning.hash_threshold` | Maximum pHash distance, from 0 to 64. Lower values are stricter. |
| `learning.similarity_threshold` | Minimum CLIP cosine similarity, from 0 to 1. Higher values are stricter. |
| `learning.training_folder` | Folder imported once at startup. |
| `enable_ocr` | Enable text recognition in image attachments. |
| `max_image_size_mb` | Maximum image attachment size to analyze. |
| `action` | `ban` or `kick`. |
| `ban_reason` | Reason written to Discord's audit log for either action. |
| `delete_message_days` | Days of the member's message history removed during a ban, from 0 to 7. |

Restart the bot after editing `config.yaml` or adding folder examples. Rebuild after changing code or dependencies: `docker compose up -d --build`.

## Data and operations

Learned examples are stored in `data/scam_db.json` and `data/examples/`. Docker mounts `data/` from the host so examples survive container restarts. Back up that directory if you need to preserve the training set.

Every detected violation attempts message deletion and the configured member action. The log records whether each operation succeeded. If bans fail, check the bot's permissions and role position. If messages are not analyzed, check Message Content Intent. If OCR is unavailable outside Docker, install Tesseract. If CLIP cannot load, hash matching remains available.

The bot token must never be committed or shared. If it is exposed, reset it in the Developer Portal.

## Tests

The test suite covers text and domain matching plus example persistence and hash matching:

```sh
python -m pytest -q
```

