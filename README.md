# YourNFC

NFC digital profiles: customers log in, edit their info, and the tag link shows it live.
This web is developed by YourNFC. 

## Setup
1. Supabase: SQL Editor > run `supabase.sql`.
2. Copy `.env.example` to `.env` and fill in SUPABASE_URL, SUPABASE_SECRET_KEY, ADMIN_KEY.
3. `npm install` then `npm start`.

## Pages
- `/login`  customer login (sign-up button shows only if ALLOW_SIGNUP=1)
- `/edit`   dashboard: edit details, photo, password, copy NFC link
- `/u/<username>`  public profile (this is what goes on the NFC tag)
- `/u/<username>.vcf`  Save contact
- `/admin`  create/reset/delete customer accounts (needs ADMIN_KEY)

## Notes
- Photos are saved to `data/uploads`. On Render/Railway set DATA_DIR to a persistent disk, or photos vanish on redeploy.
