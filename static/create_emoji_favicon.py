#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skrypt do generowania favicon z lupką emoji-podobną
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_emoji_magnifier_favicon():
    """Tworzy favicon z lupką podobną do emoji 🔍"""
    
    # Rozmiary favicon
    sizes = [16, 32, 48, 64]
    
    for size in sizes:
        # Stwórz nowy obraz z przezroczystym tłem
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Kolory jak w emoji lupki
        glass_color = (173, 216, 230, 255)      # Jasnoniebieski jak szkło
        rim_color = (105, 105, 105, 255)        # Szary metalowy obwód
        handle_color = (139, 69, 19, 255)       # Brązowy uchwyt
        
        # Skalowanie elementów
        scale = size / 32.0
        center_x = size // 2
        center_y = int(size * 0.4)  # Przesunięcie do góry
        
        # Główne koło lupy
        glass_radius = max(6, int(11 * scale))
        rim_thickness = max(1, int(2 * scale))
        
        # Narysuj szkło lupy (wypełnienie)
        draw.ellipse([
            center_x - glass_radius, 
            center_y - glass_radius,
            center_x + glass_radius, 
            center_y + glass_radius
        ], fill=glass_color)
        
        # Narysuj obwód lupy (metalowy rim)
        draw.ellipse([
            center_x - glass_radius, 
            center_y - glass_radius,
            center_x + glass_radius, 
            center_y + glass_radius
        ], outline=rim_color, width=rim_thickness)
        
        # Uchwyt lupy
        handle_length = max(8, int(12 * scale))
        handle_thickness = max(2, int(3 * scale))
        
        # Pozycja początku uchwytu (prawy dolny róg szkła)
        handle_start_x = center_x + int(glass_radius * 0.7)
        handle_start_y = center_y + int(glass_radius * 0.7)
        
        # Pozycja końca uchwytu
        handle_end_x = handle_start_x + int(handle_length * 0.8)
        handle_end_y = handle_start_y + int(handle_length * 0.8)
        
        # Narysuj uchwyt
        draw.line([handle_start_x, handle_start_y, handle_end_x, handle_end_y], 
                 fill=handle_color, width=handle_thickness)
        
        # Zakończenie uchwytu (okrągłe)
        if size >= 32:
            handle_end_radius = max(1, int(2 * scale))
            draw.ellipse([
                handle_end_x - handle_end_radius,
                handle_end_y - handle_end_radius,
                handle_end_x + handle_end_radius,
                handle_end_y + handle_end_radius
            ], fill=handle_color)
        
        # Dodaj odblaski na szkle (jak w emoji)
        if size >= 24:
            # Mały biały odblaski w lewym górnym rogu szkła
            highlight_size = max(1, int(2 * scale))
            highlight_x = center_x - int(glass_radius * 0.4)
            highlight_y = center_y - int(glass_radius * 0.4)
            
            draw.ellipse([
                highlight_x - highlight_size,
                highlight_y - highlight_size,
                highlight_x + highlight_size,
                highlight_y + highlight_size
            ], fill=(255, 255, 255, 200))
        
        # Zapisz favicon
        if size == 16:
            img.save('emoji_favicon.ico', format='ICO', sizes=[(16, 16)])
        else:
            img.save(f'emoji_favicon_{size}.png', format='PNG')
    
    # Stwórz także wersję SVG
    create_svg_emoji_magnifier()
    
    print("🔍 Favicon z lupką emoji został wygenerowany!")
    print("Pliki: emoji_favicon.ico, emoji_favicon_32.png, emoji_favicon_48.png, emoji_favicon_64.png, emoji_favicon.svg")
    print("✨ Wygląda jak emoji lupka 🔍")

def create_svg_emoji_magnifier():
    """Tworzy wersję SVG lupki emoji"""
    svg_content = '''<!-- Favicon z lupką podobną do emoji 🔍 -->
<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">
  <defs>
    <!-- Gradient dla szkła -->
    <radialGradient id="glassGradient" cx="30%" cy="30%" r="70%">
      <stop offset="0%" style="stop-color:#ffffff;stop-opacity:0.3" />
      <stop offset="70%" style="stop-color:#add8e6;stop-opacity:0.8" />
      <stop offset="100%" style="stop-color:#87ceeb;stop-opacity:1" />
    </radialGradient>
  </defs>
  
  <!-- Szkło lupy -->
  <circle cx="13" cy="13" r="9" 
          fill="url(#glassGradient)" 
          stroke="#696969" 
          stroke-width="2"/>
  
  <!-- Uchwyt lupy -->
  <line x1="20" y1="20" x2="28" y2="28" 
        stroke="#8b4513" 
        stroke-width="3" 
        stroke-linecap="round"/>
  
  <!-- Zakończenie uchwytu -->
  <circle cx="28" cy="28" r="2" fill="#8b4513"/>
  
  <!-- Odblaski na szkle -->
  <circle cx="10" cy="10" r="2" fill="#ffffff" opacity="0.6"/>
  <circle cx="8" cy="8" r="1" fill="#ffffff" opacity="0.8"/>
</svg>'''
    
    with open('emoji_favicon.svg', 'w', encoding='utf-8') as f:
        f.write(svg_content)

if __name__ == "__main__":
    create_emoji_magnifier_favicon()
