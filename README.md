# RwScanner - FiveM Security Scanner

RW ekibi tarafından kullanılan özel FiveM güvenlik ve analiz sistemi.

## Hızlı Başlangıç

### 1. Sunucuyu Başlat
```batch
start.bat
```

### 2. Oyuncu Tarama Yapar
```batch
player.bat
```
Oyuncu PIN girer, tarama otomatik yapılır, sonuçlar yetkili paneline gider.

## Varsayılan Giriş

- **Admin:** admin / admin123
- **Panel:** http://localhost:3000/panel

## Akış

1. Yetkili panelde PIN oluştur
2. PIN'i oyuncuya ver
3. Oyuncu `player.bat` ile RwScanner'ı açar
4. PIN girer
5. Tarama yapılır (oyuncuya sadece "Tamamlandı" görünür)
6. Gerçek sonuçlar yetkili panelinde görüntülenir

## Yapı

```
RwScanner/
├── start.bat           # Sunucu başlat
├── player.bat          # Oyuncu tarafı başlat
├── server/             # Backend API + Database
├── client/             # RwScanner (Node.js CLI)
│   └── src/
│       ├── app.js      # Ana uygulama
│       └── scanner/    # Tarama modülleri
├── web/                # Web paneli
│   ├── landing/        # Ana sayfa
│   └── panel/          # Yetkili paneli
└── shared/             # Paylaşılan modeller
```

## Scanner Modülleri

- **ProcessScanner** — Çalışan process analizi
- **FileScanner** — Dosya tarama
- **FiveMScanner** — FiveM ortam kontrolü
- **ResourceScanner** — Kaynak analizi
- **IntegrityScanner** — Bütünlük kontrolü
- **SignatureScanner** — İmza tabanlı tarama
