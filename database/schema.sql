CREATE TABLE IF NOT EXISTS users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id VARCHAR(32) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL
);
-- makes sure the users table exists

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'users'
          AND column_name = 'username'
    ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'users'
          AND column_name = 'user_id'
    ) THEN
        ALTER TABLE public.users RENAME COLUMN username TO user_id;
    END IF;
END
-- user id exists and changes table syntax
$$;

DO $$
BEGIN
    IF to_regclass('public.blogs') IS NULL
       AND to_regclass('public.blog_enteries') IS NOT NULL THEN
        ALTER TABLE public.blog_enteries RENAME TO blogs;
    END IF;
END
$$;

-- for the blog enteries table

CREATE TABLE IF NOT EXISTS blogs (
    blog_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    creator_name VARCHAR(255),
    creator_user_id VARCHAR(32),
    title VARCHAR(255),
    body TEXT,
    date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

SELECT id, user_id, name FROM public.users;
