# Ubuntu Sunucu Güvenlik Raporu  
# Ubuntu Server Security Report

Ubuntu sunucusunda son 12 saat içinde kaydedilen SSH saldırılarını, port taramalarını, UFW engellemelerini, Fail2ban işlemlerini, başarılı SSH girişlerini ve sudo/root hareketlerini tek raporda gösteren Bash betiğidir.

A Bash script that displays SSH attacks, port scans, UFW blocks, Fail2ban actions, successful SSH logins, and sudo/root activity recorded on an Ubuntu server during the last 12 hours in a single report.

## Özellikler / Features

- SSH saldırı ve kimlik doğrulama kayıtları
- Denenen kullanıcı adları
- Saldırgan IP adresleri
- UFW tarafından engellenen bağlantılar
- Taranan hedef portlar
- Fail2ban ban ve unban işlemleri
- Aktif Fail2ban jail durumları
- Başarılı SSH girişleri
- Sudo ve root hareketleri

## Gereksinimler / Requirements

- Ubuntu Server
- Bash
- OpenSSH
- systemd journal
- UFW
- Fail2ban

## Kullanım / Usage

Projeyi indirin:

```bash
git clone https://github.com/mrtshncom/ubuntu-sunucu-guvenlik-raporu.git
cd ubuntu-sunucu-guvenlik-raporu
