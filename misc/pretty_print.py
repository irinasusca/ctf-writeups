# pretty_print.py

# DONT USE THIS IF YOU NEED PERFORMANCE
# obviously its not that big of a deal, just keep that in mind.
# this uses rich for text coloring and so on.
import re
from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel
from rich.theme import Theme

#in case you want to customize your own theme

custom_theme = Theme({
    "info": "hot_pink",
    "url": "pale_violet_red1 underline",
    "status_ok": "spring_green3",
    "status_error": "deep_pink3",
    "border_normal": "magenta",
    "border_flag": "hot_pink",
    "flag_text": "blink bold hot_pink",
    "lexer_info": "dim"
})

console = Console(theme=custom_theme)

def pretty_print(res):

    # status summary
    status_style = "status_ok" if res.status_code < 300 else "status_error"
    console.print(f"[{status_style}] {res.status_code} {res.reason} [/{status_style}] | [url]{res.url}[/url]")

    # content type for the highlighter
    ctype = res.headers.get('Content-Type', '').lower()
    lexer = "json" if "json" in ctype else "html" if "html" in ctype else "text"

    # look for the flag with regex. 
    flag_patterns = r"(ctf|unr|ocsc|ocsj|rocsc|flag|\w+\{.*?\})"
    found_flag = re.search(flag_patterns, res.text, re.IGNORECASE)

    # prepare the Body
    syntax = Syntax(res.text, lexer, theme="dracula", word_wrap=True)
    
    if found_flag:
        title = f"[flag_text]🚩 POTENTIAL FLAG DETECTED: {found_flag.group(0)}[/flag_text]"
        border_style = "border_flag"
    else:
        title = f"[lexer_info]{lexer} output[/lexer_info]"
        border_style = "border_normal"

    # print the result
    console.print(Panel(syntax, title=title, border_style=border_style))
