"""
modules/db.py
--------------
Supabase (Postgres) client üçün tək mərkəzi giriş nöqtəsi.

Bu modulu `modules/storage.py` istifadə edir. `SUPABASE_URL` və/ya
`SUPABASE_KEY` mühit dəyişənləri (.env / Streamlit Cloud Secrets) təyin
olunmayıbsa, `get_client()` None qaytarır — çağıran tərəf (storage.py)
bunu uyğun şəkildə idarə edir (boş nəticə, UI-da xəbərdarlıq) ki, tətbiq
Supabase hələ qoşulmadan belə CRASH etməsin.

QEYD (təhlükəsizlik): `SUPABASE_KEY` kimi `service_role` key istifadə
etmək tövsiyə olunur, çünki Streamlit server-side render edir — bu key
heç vaxt brauzerə/istifadəçiyə ötürülmür, yalnız bu Python prosesində
qalır (fərqli olaraq saf client-side JS tətbiqlərindən, orada `anon`
key + Row Level Security tələb olunurdu).
"""
from functools import lru_cache

from modules import config


@lru_cache(maxsize=1)
def get_client():
    """Supabase client-i yaradır (bir dəfə, keşlənir). Konfiqurasiya
    yoxdursa və ya `supabase` paketi quraşdırılmayıbsa, None qaytarır."""
    if not config.SUPABASE_URL or not config.SUPABASE_KEY:
        return None
    try:
        from supabase import create_client
        return create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
    except Exception as e:
        print(f"[db] Supabase client yaradıla bilmədi: {e}")
        return None


def is_configured() -> bool:
    """UI-da ('⚠️ Supabase qoşulmayıb' kimi) xəbərdarlıq göstərmək üçün istifadə olunur."""
    return get_client() is not None
