import streamlit as st
import psycopg
import bcrypt
from datetime import datetime, time
import re
import pandas as pd 

from supabase import create_client, Client  # used ONLY for Storage bytes in this setup

st.set_page_config(page_title="INP Projects", layout="wide")

# =========================
# Config
# =========================
DB_URL = st.secrets["SUPABASE_DB_URL"]  # MUST be app_client role (no bypassrls)
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SERVICE_ROLE_KEY = st.secrets["SUPABASE_SERVICE_ROLE_KEY"]  # storage only
BUCKET = st.secrets.get("BUCKET_NAME", "project_uploads")

# Storage client (server-side)
storage_sb: Client = create_client(SUPABASE_URL, SERVICE_ROLE_KEY)


def is_project_owner(conn, user_id: str, project_id: str) -> bool:
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, "select public.is_project_owner(%s);", (project_id,))
        row = cur.fetchone()
        cur.close()
        return bool(row and row[0])
    except Exception:
        cur.close()
        return False


def has_project_access(conn, user_id: str, project_id: str) -> bool:
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, "select public.has_project_access(%s);", (project_id,))
        row = cur.fetchone()
        cur.close()
        return bool(row and row[0])
    except Exception:
        cur.close()
        return False


# =========================
# Helpers
# =========================
def safe_project_name_id(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"[^\w\-]+", "_", s)  # letters/numbers/_/-
    return s

def require_inp(uploaded_file) -> None:
    if uploaded_file is None:
        raise ValueError("No file selected.")
    if not uploaded_file.name.lower().endswith(".inp"):
        raise ValueError("Only .inp files are allowed.")

# =========================
# Validators & constants
# =========================
ALLOWED_SPATIAL_EXTS = [".zip", ".geojson", ".gpkg", ".json"]  # zip (shapefile bundle), GeoJSON, GeoPackage

ALLOWED_LID_COLUMNS = [
    "Bioretention",
    "RainGarden",
    "GreenRoof",
    "InfiltrationTrench",
    "PermeablePavement",
    "RainBarrel",
    "VegetativeSwale",
]
# Synonym mapping -> canonical names
LID_CANONICAL = {
    "Bioretention": "Bioretention",
    "BioRetention": "Bioretention",
    "RainGarden": "RainGarden",
    "GreenRoof": "GreenRoof",
    "InfiltrationTrench": "InfiltrationTrench",
    "PermeablePavement": "PermeablePavement",
    "RainBarrel": "RainBarrel",
    "Cistern": "RainBarrel",
    "VegetativeSwale": "VegetativeSwale",
}

def require_spatial(uploaded_file, layer_label: str):
    if uploaded_file is None:
        raise ValueError(f"No {layer_label} file selected.")
    name = uploaded_file.name.lower()
    if not any(name.endswith(ext) for ext in ALLOWED_SPATIAL_EXTS):
        raise ValueError(f"{layer_label} must be one of: {', '.join(ALLOWED_SPATIAL_EXTS)}")

def require_excel_or_csv(uploaded_file):
    if uploaded_file is None:
        raise ValueError("No file selected.")
    name = uploaded_file.name.lower()
    if not (name.endswith(".csv") or name.endswith(".xlsx") or name.endswith(".xls")):
        raise ValueError("Only .csv, .xlsx, or .xls files are allowed.")

def normalize_resolution(val: str) -> str:
    v = (val or "").strip().lower()
    return {"low": "low", "moderate": "moderate", "high": "high"}.get(v, "moderate")

def normalize_network_source(val: str) -> str:
    v = (val or "").strip().lower()
    mapping = {
        "as built": "as_built",
        "as_built": "as_built",
        "legacy gis": "legacy_gis",
        "legacy_gis": "legacy_gis",
        "partial": "partial",
        "mixed": "mixed",
    }
    return mapping.get(v, "mixed")

def normalize_confidence(val: str) -> str:
    v = (val or "").strip().lower()
    return {"low": "low", "moderate": "moderate", "high": "high"}.get(v, "moderate")

def classify_confidence(q: dict) -> str:
    score = 0
    if q.get("calibrated_to_gage"): score += 2
    if int(q.get("validated_events", 0)) >= 1: score += 2
    if normalize_resolution(q.get("input_resolution")) == "high": score += 1
    if normalize_network_source(q.get("network_source")) == "as_built": score += 1
    if normalize_confidence(q.get("confidence_self")) == "high": score += 1
    return "high" if score >= 6 else "moderate" if score >= 3 else "low"


def bcrypt_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def bcrypt_check(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

import psycopg

def get_conn():
    # Turn OFF server-side prepared statements; keep autocommit for PgBouncer
    # (If you’re on Supabase 6543 pooled port, this is the correct setting.)
    return psycopg.connect(
        st.secrets["SUPABASE_DB_URL"],
        prepare_threshold=None
    )

def try_get_conn():
    """Return a live connection or None; do NOT crash the page."""
    try:
        conn = get_conn()
        conn.autocommit = True
        return conn
    except Exception as e:
        # Show a friendly message and provide the technical type for debugging
        st.warning("We couldn’t connect to the database right now.")
        st.caption(f"Technical detail: {type(e).__name__}: {e}")
        return None


def _cursor(conn):
    # Prefer text protocol to avoid binary/extended behaviors
    return conn.cursor(binary=False)

def qexec(cur, sql: str, params: tuple | None = None):
    return cur.execute(sql, params or ())

def qexecmany(cur, sql: str, seq_params: list[tuple]):
    # Avoid executemany (can lead to implicit prepares)
    for p in seq_params:
        cur.execute(sql, p)

def set_rls_user(cur, user_id: str | None):
    """
    Set app.user_id RLS context at the *session* level (is_local=false)
    so we don't need transactions. PgBouncer-safe.
    """
    uid = str(user_id) if user_id else ""
    cur.execute("select set_config('app.user_id', %s, false);", (uid,))


import mimetypes

def detect_content_type(filename: str) -> str:
    name = filename.lower()
    # specific overrides
    if name.endswith(".inp"):
        return "text/plain"
    if name.endswith(".zip"):
        return "application/zip"
    if name.endswith(".geojson"):
        return "application/geo+json"
    if name.endswith(".json"):
        return "application/json"
    if name.endswith(".gpkg"):
        return "application/octet-stream"
    if name.endswith(".csv"):
        return "text/csv"
    if name.endswith(".xlsx"):
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    if name.endswith(".xls"):
        return "application/vnd.ms-excel"
    # fallback
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"

def supabase_upload_bytes(bucket: str, path: str, filename: str, data: bytes, upsert: bool = True):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Upload data must be bytes.")
    ct = detect_content_type(filename) or "application/octet-stream"
    options = {
        "contentType": ct,
        "cacheControl": "3600",
        "upsert": "true" if upsert else "false",
    }
    return storage_sb.storage.from_(bucket).upload(path, data, options)
# =========================
# Auth via SECURITY DEFINER RPCs (RLS-safe)
# =========================

def rpc_lookup_user_for_login(conn, email: str):
    email = email.strip().lower()
    cur = _cursor(conn)
    try:
        set_rls_user(cur, None)  # not authenticated yet
        qexec(cur, "select user_id, bcrypt_hash from public.lookup_user_for_login(%s);", (email,))
        row = cur.fetchone()
        cur.close()
        return row
    except Exception:
        cur.close()
        raise

def rpc_create_user(conn, email: str, password: str) -> bool:
    email = email.strip().lower()
    h = bcrypt_hash(password)
    cur = _cursor(conn)
    try:
        set_rls_user(cur, None)
        qexec(cur, "select public.create_user(%s, %s);", (email, h))
        cur.close()
        return True
    except Exception:
        cur.close()
        return False

def rpc_change_password(conn, user_id: str, new_password: str) -> bool:
    h = bcrypt_hash(new_password)
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, "select public.change_password(%s);", (h,))
        cur.close()
        return True
    except Exception:
        cur.close()
        return False


# =========================
# DB ops (all RLS enforced)
# =========================

def db_list_projects(conn, user_id: str):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, """
            select id, project_name_id, project_title, deletable_after, created_at, updated_at
            from public.projects
            order by created_at desc;
        """)
        rows = cur.fetchall()
        cur.close()
        return rows
    except Exception:
        cur.close()
        raise


def db_create_project(conn, user_id: str, project_name_id: str, title: str | None):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, """
            insert into public.projects (user_id, project_name_id, project_title)
            values (%s, %s, %s)
            returning id;
        """, (user_id, project_name_id, title))
        pid = cur.fetchone()[0]
        cur.close()
        return str(pid)
    except Exception:
        cur.close()
        raise

def db_set_deletable_after(conn, user_id: str, project_id: str, deletable_after: datetime | None):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, """
            update public.projects
            set deletable_after = %s
            where id = %s;
        """, (deletable_after, project_id))
        cur.close()
    except Exception:
        cur.close()
        raise



def db_get_current_file(conn, user_id: str, project_id: str):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, """
            select id, storage_path, original_filename, updated_at
            from public.project_files
            where project_id = %s;
        """, (project_id,))
        row = cur.fetchone()
        cur.close()
        return row
    except Exception:
        cur.close()
        raise

def db_upsert_current_file(conn, user_id: str, project_id: str, storage_path: str, original_filename: str):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, """
            insert into public.project_files (user_id, project_id, storage_path, original_filename)
            values (%s, %s, %s, %s)
            on conflict (project_id)
            do update set storage_path = excluded.storage_path,
                        original_filename = excluded.original_filename;
        """, (user_id, project_id, storage_path, original_filename))
        cur.close()
    except Exception:
        cur.close()
        raise


def db_delete_current_file_row(conn, user_id: str, project_id: str):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, """
            delete from public.project_files
            where project_id = %s
            returning storage_path;
        """, (project_id,))
        row = cur.fetchone()
        cur.close()
        return row[0] if row else None
    except Exception:
        cur.close()
        raise

def db_rename_project_name_id(conn, user_id: str, project_id: str, new_name_id: str):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, """
            update public.projects
            set project_name_id = %s
            where id = %s;
        """, (new_name_id, project_id))
        cur.close()
    except Exception:
        cur.close()
        raise


# =========================
# DB ops: spatial layers, LID caps, uncertainty
# =========================

def db_upsert_spatial_layer(conn, user_id: str, project_id: str, layer_type: str, storage_path: str, original_filename: str):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, "delete from public.project_spatial_layers where project_id = %s and layer_type = %s;", (project_id, layer_type))
        qexec(cur, """
            insert into public.project_spatial_layers (user_id, project_id, layer_type, storage_path, original_filename)
            values (%s, %s, %s, %s, %s);
        """, (user_id, project_id, layer_type, storage_path, original_filename))
        cur.close()
    except Exception:
        cur.close()
        raise

def db_replace_lid_caps(conn, user_id: str, project_id: str, rows: list[tuple[str, str, float]]):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, "delete from public.project_lid_caps where project_id = %s;", (project_id,))
        qexecmany(cur, """
            insert into public.project_lid_caps (user_id, project_id, subcatchment_id, lid_type, max_value)
            values (%s, %s, %s, %s, %s);
        """, [(user_id, project_id, sc, lid, float(mx)) for (sc, lid, mx) in rows])
        cur.close()
    except Exception:
        cur.close()
        raise

def db_upsert_uncertainty(conn, user_id: str, project_id: str, q: dict, confidence_class: str):
    cur = _cursor(conn)
    try:
        set_rls_user(cur, user_id)
        qexec(cur, """
            insert into public.project_uncertainty
            (project_id, user_id,
             calibrated_to_gage, validated_events, input_resolution, network_source,
             confidence_self, percent_uncertainty, notes, confidence_class)
            values
            (%s, %s,
             %s, %s, %s, %s,
             %s, %s, %s, %s)
            on conflict (project_id) do update
            set calibrated_to_gage = excluded.calibrated_to_gage,
                validated_events   = excluded.validated_events,
                input_resolution   = excluded.input_resolution,
                network_source     = excluded.network_source,
                confidence_self    = excluded.confidence_self,
                percent_uncertainty= excluded.percent_uncertainty,
                notes              = excluded.notes,
                confidence_class   = excluded.confidence_class,
                updated_at         = now();
        """, (
            project_id, user_id,
            bool(q.get("calibrated_to_gage")),
            int(q.get("validated_events", 0)),
            normalize_resolution(q.get("input_resolution")),
            normalize_network_source(q.get("network_source")),
            normalize_confidence(q.get("confidence_self")),
            float(q.get("percent_uncertainty") or 0.0),  # 👉 NEW param
            q.get("notes") or "",
            confidence_class
        ))
        cur.close()
    except Exception as e:
        cur.close()
        raise e

# =========================
# UI: Auth
# =========================
def auth_ui():
    st.title("INP Projects")

    tabs = st.tabs(["Login", "Create account", "Change password"])
    with tabs[0]:
        email = st.text_input("Email", key="login_email")
        pw = st.text_input("Password", type="password", key="login_pw")
        if st.button("Login", use_container_width=True):
            conn = get_conn()
            try:
                row = rpc_lookup_user_for_login(conn, email)
            except Exception as e:
                st.error(f"Login lookup failed: {e}")
                return
            finally:
                conn.close()

            if not row:
                st.error("Invalid email or password.")
                return

            user_id, hashed = row
            if bcrypt_check(pw, hashed):
                st.session_state["user_id"] = str(user_id)
                st.session_state["email"] = email.strip().lower()
                st.success("Logged in.")
                st.rerun()
            else:
                st.error("Invalid email or password.")

    with tabs[1]:
        email = st.text_input("Email", key="signup_email")
        pw1 = st.text_input("Password", type="password", key="signup_pw1")
        pw2 = st.text_input("Confirm password", type="password", key="signup_pw2")
        if st.button("Create account", use_container_width=True):
            if pw1 != pw2:
                st.error("Passwords do not match.")
                return
            if len(pw1) < 8:
                st.error("Use at least 8 characters.")
                return

            conn = get_conn()
            try:
                ok = rpc_create_user(conn, email, pw1)
            finally:
                conn.close()


            if ok:
                st.success("Account created. Now log in.")
            else:
                st.error("Could not create account (email may already exist).")


    with tabs[2]:
        st.caption("No email reset. Requires current password.")
        email = st.text_input("Email", key="cp_email")
        old_pw = st.text_input("Current password", type="password", key="cp_old_pw")
        new_pw1 = st.text_input("New password", type="password", key="cp_new_pw1")
        new_pw2 = st.text_input("Confirm new password", type="password", key="cp_new_pw2")

        if st.button("Change password", use_container_width=True):
            if new_pw1 != new_pw2:
                st.error("New passwords do not match.")
                return
            if len(new_pw1) < 8:
                st.error("Use at least 8 characters.")
                return

            conn = get_conn()
            try:
                row = rpc_lookup_user_for_login(conn, email)
                if not row:
                    st.error("Invalid email or password.")
                    return
                user_id, hashed = row
                if not bcrypt_check(old_pw, hashed):
                    st.error("Invalid email or password.")
                    return

                ok = rpc_change_password(conn, str(user_id), new_pw1)
                if ok:
                    st.success("Password changed.")
                else:
                    st.error("Could not change password.")
            finally:
                conn.close()

# =========================
# UI: App
# =========================
def app_ui(user_id: str, email: str):
    st.sidebar.success(f"Logged in: {email}")
    if st.sidebar.button("Logout"):
        st.session_state.pop("user_id", None)
        st.session_state.pop("email", None)
        st.rerun()

    st.title("Your Projects (.inp)")

    conn = None
    try:
        conn = try_get_conn()
        if conn is None:
            # We already surfaced a warning in try_get_conn(); stop rendering
            return
        # Create project
        with st.expander("Create project", expanded=True):
            raw_name = st.text_input("Project ID", placeholder="e.g. HavenCreek_Watershed_01")
            title = st.text_input("Project title (optional)")
            if st.button("Create project", use_container_width=True):
                name_id = safe_project_name_id(raw_name)
                if not name_id:
                    st.error("Project ID name is required.")
                else:
                    try:
                        db_create_project(conn, user_id, name_id, title.strip() or None)
                        st.success("Project created.")
                        st.rerun()
                    except Exception as e:
                        st.error(str(e))

        # List projects
        try:
            projects = db_list_projects(conn, user_id)
        except Exception as e:
            st.error(f"Could not load projects: {e}")
            return

        if not projects:
            st.info("No projects yet. Create one above to upload a file.")
            return

        labels = []
        proj_map = {}
        for (pid, name_id, ptitle, deletable_after, created_at, updated_at) in projects:
            label = f"{name_id}  ({str(pid)[:8]})"
            labels.append(label)
            proj_map[label] = {
                "id": str(pid),
                "name_id": name_id,
                "title": ptitle,
                "deletable_after": deletable_after,
            }

        selected = st.selectbox("Select project", labels, key="selected_project_label")
        proj = proj_map[selected]
        project_id = proj["id"]
        project_name_id = proj["name_id"]

        st.subheader(f"Project: {project_name_id}")
        if proj["title"]:
            st.caption(proj["title"])

        # Rename ID + move storage file if exists
        with st.expander("Rename project ID", expanded=False):
            new_raw = st.text_input("New Project ID", value=project_name_id, key="rename_pid")
            if st.button("Rename", use_container_width=True):
                new_name_id = safe_project_name_id(new_raw)
                if not new_name_id:
                    st.error("Invalid name.")
                else:
                    try:
                        current = db_get_current_file(conn, user_id, project_id)
                        old_path = current[1] if current else None

                        if old_path:
                            new_path = f"users/{user_id}/projects/{new_name_id}/current.inp"
                            storage_sb.storage.from_(BUCKET).move(old_path, new_path)
                            db_upsert_current_file(conn, user_id, project_id, new_path, current[2])

                        db_rename_project_name_id(conn, user_id, project_id, new_name_id)
                        st.success("Renamed.")
                        st.rerun()
                    except Exception as e:
                        st.error(str(e))

        # deletable_after date
        with st.expander("Admin deletion date (admin will delete your files after this date)", expanded=False):
            dt = st.date_input("Deletable after date (optional)", value=None, key="del_after_date")
            if st.button("Save deletion date", use_container_width=True):
                deletable_after = None
                if dt:
                    deletable_after = datetime.combine(dt, time.min)
                try:
                    db_set_deletable_after(conn, user_id, project_id, deletable_after)
                    st.success("Saved.")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

        # Current file
        st.divider()
        st.subheader("Current file")

        current = db_get_current_file(conn, user_id, project_id)
        if current:
            file_id, storage_path, original_filename, updated_at = current
            st.write(f"**{original_filename}**")


            # Gate sensitive actions to owners only
            owner = is_project_owner(conn, user_id, project_id)
            if owner and st.button("Delete current file", use_container_width=True):
                    try:
                        path = db_delete_current_file_row(conn, user_id, project_id)
                        if path:
                            storage_sb.storage.from_(BUCKET).remove([path])
                        st.success("Deleted.")
                        st.rerun()
                    except Exception as e:
                        st.error(str(e))
            elif not owner:
                    st.info("Delete available to project owners only.")

        # Upload overwrite
        st.divider()
        st.subheader("Upload / overwrite current.inp")

        up = st.file_uploader("Choose .inp", type=["inp"])
        if st.button("Upload (overwrite)", use_container_width=True):
            try:
                require_inp(up)
                storage_path = f"users/{user_id}/projects/{project_name_id}/current.inp"
                supabase_upload_bytes(
                    BUCKET,
                    storage_path,
                    up.name,
                    up.getvalue(),
                    upsert=True
                )
                db_upsert_current_file(conn, user_id, project_id, storage_path, up.name)
                st.success("Uploaded / overwritten.")
                st.rerun()
            except Exception as e:
                st.error(str(e))

        # =========================
        # Spatial Layers (Watershed, Pipes, Inlets/Outfalls)
        # =========================
        st.divider()
        st.subheader("Spatial Layers: Sub-Watersheds, Stormwater Pipes, Inlets/Outfalls")

        st.caption("Accepted: zipped shapefile (.zip), GeoJSON (.geojson/.json), or GeoPackage (.gpkg). "
                "For shapefiles, upload a single .zip containing .shp/.dbf/.shx/.prj.")

        # Gate uploads to owners, but let testers view info
        owner = is_project_owner(conn, user_id, project_id)

        col_w, col_p, col_o = st.columns(3)
        with col_w:
            watershed_file = st.file_uploader("Watershed layer", type=["zip", "geojson", "gpkg", "json"], key="watershed_file")
            if owner and st.button("Upload Sub-Watersheds", use_container_width=True, key="btn_watershed"):
                try:
                    require_spatial(watershed_file, "Watershed")
                    storage_path = f"users/{user_id}/projects/{project_name_id}/spatial/watershed/{watershed_file.name}"
                    supabase_upload_bytes(
                        BUCKET,
                        storage_path,
                        watershed_file.name,  # or pipes_file.name / outfalls_file.name
                        watershed_file.getvalue(),
                        upsert=True
                    )
                    db_upsert_spatial_layer(conn, user_id, project_id, "watershed", storage_path, watershed_file.name)
                    st.success("Sub-Watersheds layer uploaded.")
                except Exception as e:
                    st.error(str(e))
            elif not owner and watershed_file is not None:
                st.info("Upload reserved for project owners.")

        with col_p:
            pipes_file = st.file_uploader("Pipes layer", type=["zip", "geojson", "gpkg", "json"], key="pipes_file")
            if owner and st.button("Upload Stormwater Pipes", use_container_width=True, key="btn_pipes"):
                try:
                    require_spatial(pipes_file, "Pipes")
                    storage_path = f"users/{user_id}/projects/{project_name_id}/spatial/pipes/{pipes_file.name}"
                    supabase_upload_bytes(
                        BUCKET,
                        storage_path,
                        pipes_file.name,
                        pipes_file.getvalue(),
                        upsert=True
                    )
                    db_upsert_spatial_layer(conn, user_id, project_id, "pipes", storage_path, pipes_file.name)
                    st.success("Pipes layer uploaded.")
                except Exception as e:
                    st.error(str(e))
            elif not owner and pipes_file is not None:
                st.info("Upload reserved for project owners.")

        with col_o:
            outfalls_file = st.file_uploader("Inlets/Outfalls layer", type=["zip", "geojson", "gpkg", "json"], key="outfalls_file")
            if owner and st.button("Upload Inlets/Outfalls", use_container_width=True, key="btn_outfalls"):
                try:
                    require_spatial(outfalls_file, "Inlets/Outfalls")
                    storage_path = f"users/{user_id}/projects/{project_name_id}/spatial/outfalls/{outfalls_file.name}"
                    supabase_upload_bytes(
                        BUCKET,
                        storage_path,
                        outfalls_file.name,
                        outfalls_file.getvalue(),
                        upsert=True
                    )
                    db_upsert_spatial_layer(conn, user_id, project_id, "outfalls", storage_path, outfalls_file.name)
                    st.success("Inlets/Outfalls layer uploaded.")
                except Exception as e:
                    st.error(str(e))
            elif not owner and outfalls_file is not None:
                st.info("Upload reserved for project owners.")
        # =========================
        # LID Upper Bounds per Subcatchment (Excel/CSV)
        # =========================
        st.divider()
        st.subheader("LID Upper Bound (Max) per Subcatchment")

        st.caption("Upload a CSV or Excel with column 'Subcatchment' plus one or more LID columns: "
                + ", ".join(ALLOWED_LID_COLUMNS))

        # Simple CSV template for users
        template_df = pd.DataFrame({
            "Subcatchment": ["S1", "S2", "S3"],
            "Bioretention": [10, 5, 0],
            "RainGarden": [0, 3, 1],
            "GreenRoof": [0, 0, 0],
            "InfiltrationTrench": [2, 0, 0],
            "PermeablePavement": [0, 0, 12],
            "RainBarrel": [4, 4, 4],
            "VegetativeSwale": [0, 1, 0],
        })
        tmpl_bytes = template_df.to_csv(index=False).encode()
        st.download_button("Download CSV Template", data=tmpl_bytes, file_name="lid_upper_bound_template.csv", mime="text/csv")

        lid_file = st.file_uploader("Upload LID Upper Bound (.csv, .xlsx, .xls)", type=["csv", "xlsx", "xls"], key="lid_caps_file")

        def parse_lid_caps(file) -> list[tuple[str, str, float]]:
            name = file.name.lower()
            if name.endswith(".csv"):
                df = pd.read_csv(file)
            else:
                df = pd.read_excel(file)
            if "Subcatchment" not in df.columns:
                raise ValueError("Missing required 'Subcatchment' column.")
            # Validate LID columns
            for col in df.columns:
                if col == "Subcatchment": continue
                canon = LID_CANONICAL.get(col, None)
                if canon is None or canon not in ALLOWED_LID_COLUMNS:
                    raise ValueError(f"Unexpected LID column '{col}'. Allowed: {', '.join(ALLOWED_LID_COLUMNS)}")
            # Build normalized rows
            rows = []
            for _, r in df.iterrows():
                sc = str(r["Subcatchment"]).strip()
                if not sc:
                    raise ValueError("Empty subcatchment id encountered.")
                for lid_col in ALLOWED_LID_COLUMNS:
                    if lid_col in df.columns:
                        val = r[lid_col]
                        if pd.isna(val):
                            continue
                        try:
                            v = float(val)
                        except Exception:
                            raise ValueError(f"Non-numeric value in '{lid_col}' for subcatchment '{sc}'.")
                        if v < 0:
                            raise ValueError(f"Negative value in '{lid_col}' for subcatchment '{sc}'.")
                        rows.append((sc, lid_col, v))
            return rows

        owner = is_project_owner(conn, user_id, project_id)

        if owner and st.button("Save LID upper bound file", use_container_width=True, key="btn_save_lids"):
            try:
                require_excel_or_csv(lid_file)
                rows = parse_lid_caps(lid_file)
                # Save original file for traceability
                storage_path = f"users/{user_id}/projects/{project_name_id}/lid_caps/{lid_file.name}"
                supabase_upload_bytes(
                    BUCKET,
                    storage_path,
                    lid_file.name,
                    lid_file.getvalue(),
                    upsert=True
                )
                db_replace_lid_caps(conn, user_id, project_id, rows)
                st.success(f"Saved {len(rows)} LID upper bound entries.")
            except Exception as e:
                st.error(str(e))
        elif not owner and lid_file is not None:
            st.info("Upload reserved for project owners.")

        # =========================
        # Uncertainty Questionnaire
        # =========================
        st.divider()
        st.subheader("Uncertainty Questionnaire")

        owner = is_project_owner(conn, user_id, project_id)

        with st.form("uncertainty_form", clear_on_submit=False):
            c_gage   = st.checkbox("Calibrated to at least one gage?")
            v_events = st.number_input("Number of validated events", min_value=0, max_value=1000, step=1, value=0)
            input_res = st.selectbox("Input resolution", ["Low", "Moderate", "High"])
            with st.popover("What do Low / Moderate / High mean?"):
                st.markdown("""
            **Low**  
            - Coarse inputs (≥10–30 m land cover), coarse DEM  
            - Generalized subcatchments, limited detail  
            - Higher uncertainty; screening only

            **Moderate**  
            - Planning-grade inputs (1–10 m land cover, 1–3 m DEM)  
            - Good for watershed screening and comparison

            **High**  
            - High-resolution inputs (<1 m LiDAR DEM)  
            - Detailed land use & surveyed impervious datasets  
            - Suitable for design-grade assessments
            """)

            net_src = st.selectbox("Stormwater network source", ["As Built", "Legacy GIS", "Partial", "Mixed"])
            with st.popover("What do the network source options mean?"):
                st.markdown("""
            **As Built**  
            - Digitized from engineered as‑built drawings or surveyed field data  
            - Highest accuracy

            **Legacy GIS**  
            - Older stormwater GIS dataset; may be incomplete/outdated  
            - Attributes (sizes/slopes/connectivity) can be wrong

            **Partial**  
            - Only part of the network (e.g., trunk lines) is represented  
            - Missing laterals/segments; limited connectivity

            **Mixed**  
            - Combination of the above; quality varies across the system
            """)
            conf_self = st.selectbox("Your confidence (self-rating)", ["Low", "Moderate", "High"])           
            percent_uncertainty = st.number_input(
                "Model-estimated flooding uncertainty (%)",
                min_value=0.0, max_value=100.0, step=0.1, value=0.0,
                help="Enter a single percentage representing your model’s estimated flooding uncertainty."
            )            
            notes = st.text_area("Notes / metadata (optional)", placeholder="e.g., validated on Hurricane Irene (2011); high-res land use")

            submitted = st.form_submit_button("Save Uncertainty")
            if submitted:
                owner = is_project_owner(conn, user_id, project_id)
                if not owner:
                    st.error("Only project owners can save uncertainty metadata.")
                else:
                    try:
                        q = {
                            "calibrated_to_gage": c_gage,
                            "validated_events": v_events,
                            "input_resolution": input_res,
                            "network_source": net_src,
                            "confidence_self": conf_self,
                            "percent_uncertainty": percent_uncertainty,
                            "notes": notes
                        }
                        cclass = classify_confidence(q)
                        db_upsert_uncertainty(conn, user_id, project_id, q, cclass)
                        st.success(f"Saved. Confidence class: **{cclass.capitalize()}**")
                    except Exception as e:
                        st.error(str(e))
    

    finally:
        if conn is not None:  
            conn.close()

# =========================
# Main
# =========================
user_id = st.session_state.get("user_id")
email = st.session_state.get("email")

if not user_id:
    auth_ui()
else:
    app_ui(user_id, email or "")
