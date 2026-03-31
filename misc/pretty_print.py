# pretty_print.py

# DONT USE THIS IF YOU NEED PERFORMANCE
# obviously its not that big of a deal, just keep that in mind.
# this uses rich for text coloring and so on.
import re
from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel
from rich.theme import Theme

#in case you want to customize your own theme, or choose one I made, just modify the "selection" var

themes = {
    "default": {
        "rich": Theme({
            "status_ok": "green",
            "status_error": "red",
            "url_dim": "dim",
            "border_normal": "blue",
            "border_flag": "bright_magenta",
            "flag_text": "blink bold yellow",
            "lexer_info": "dim"
        }),
        "syntax": "monokai"
    },
    "pink": {
        "rich": Theme({
   	    "info": "hot_pink",
    	    "url": "pale_violet_red1 underline",
    	    "status_ok": "spring_green3",
    	    "status_error": "deep_pink3",
    	    "border_normal": "magenta",
    	    "border_flag": "hot_pink",
    	    "flag_text": "blink bold hot_pink",
    	    "lexer_info": "dim"
	}),
        "syntax": "dracula"
    },
    "arctic": {
        "rich": Theme({
            "status_ok": "medium_spring_green",  
            "status_error": "indian_red",        
            "url_dim": "light_sky_blue1 underline dim",
            "border_normal": "steel_blue",       
            "border_flag": "cyan1",              
            "flag_text": "bold black on cyan1", 
            "lexer_info": "grey70"
        }),
        "syntax": "nord"  
    }
}

# SELECT YOUR THEME HERE!
selection = "pink"  # "pink" or "default" etc
active = themes[selection]
console = Console(theme=active["rich"])


def pretty_print(res):

    # status summary
    status_style = "status_ok" if res.status_code < 300 else "status_error"
    console.print(f"[{status_style}] {res.status_code} {res.reason} [/{status_style}] | [url]{res.url}[/url]")

    # content type for the highlighter
    ctype = res.headers.get('Content-Type', '').lower()
    lexer = "json" if "json" in ctype else "html" if "html" in ctype else "text"

    # look for the flag with regex. 
    flag_patterns = r"\b(ctf|unr|ocsc|ocsj|rocsc|flag)\{.*?\}"
    found_flag = re.search(flag_patterns, res.text, re.IGNORECASE)

    # prepare the Body
    syntax = Syntax(res.text, lexer, theme=active["syntax"], word_wrap=True)
    
    if found_flag:
        title = f"[flag_text]🚩 POTENTIAL FLAG DETECTED: {found_flag.group(0)}[/flag_text]"
        border_style = "border_flag"
    else:
        title = f"[lexer_info]{lexer} output[/lexer_info]"
        border_style = "border_normal"

    # print the result
    console.print(Panel(syntax, title=title, border_style=border_style))
