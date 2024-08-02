import re

def extract_translate_keys(filepath):
    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()
    return re.findall(r'i18n\.Translate\("([^"]+)"', content)

def extract_translations(filepath):
    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()
    language_sections = re.findall(r'"(\w+)":\s*{([^}]*)}', content)
    translations = {}
    for lang, keys_str in language_sections:
        keys = re.findall(r'"([^"]+)":', keys_str)
        translations[lang] = keys
    return translations

def print_keys(title, keys):
    if keys:
        print(f"{title}:")
        for key in sorted(keys):
            print(f"  {key}")
    else:
        print(f"{title}: None")

def main():
    main_go_keys = extract_translate_keys('main.go')
    translations = extract_translations('translations.go')

    main_go_keys_set = set(main_go_keys)

    for lang, lang_keys in translations.items():
        lang_keys_set = set(lang_keys)
        
        missing_keys = main_go_keys_set - lang_keys_set
        extra_keys = lang_keys_set - main_go_keys_set

        print(f"\n--- {lang} Translations ---")
        print_keys("Missing keys", missing_keys)
        print_keys("Extra keys", extra_keys)

if __name__ == "__main__":
    main()