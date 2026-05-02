
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*" >&2; }
banner()  { echo -e "\n${BOLD}${BLUE}──────────────────────────────────────────${NC}"; echo -e "${BOLD}  $*${NC}"; echo -e "${BOLD}${BLUE}──────────────────────────────────────────${NC}\n"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Ce script doit être exécuté en tant que root."
        echo "  → Relancez avec : sudo bash $0"
        exit 1
    fi
}

# ── OS Detection ─────────────────────────────────────────────────────────────
detect_os() {
    OS_ID=""
    OS_VERSION=""
    PKG_MGR=""

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-0}"
        OS_NAME="${PRETTY_NAME:-$OS_ID}"
    else
        OS_ID="unknown"
        OS_NAME="Unknown Linux"
    fi

    if   command -v apt-get &>/dev/null; then PKG_MGR="apt"
    elif command -v dnf     &>/dev/null; then PKG_MGR="dnf"
    elif command -v yum     &>/dev/null; then PKG_MGR="yum"
    elif command -v zypper  &>/dev/null; then PKG_MGR="zypper"
    elif command -v pacman  &>/dev/null; then PKG_MGR="pacman"
    else                                      PKG_MGR="none"
    fi

    KERNEL_VERSION=$(uname -r)

    info "Système détecté : ${BOLD}${OS_NAME}${NC}"
    info "Noyau courant   : ${BOLD}${KERNEL_VERSION}${NC}"
    info "Gestionnaire    : ${BOLD}${PKG_MGR}${NC}"
}

check_vulnerability() {
    banner "Vérification de la vulnérabilité"

    if [[ "$OS_ID" == "ubuntu" ]]; then
        local major minor
        major=$(echo "$OS_VERSION" | cut -d. -f1)
        if [[ "$major" -ge 26 ]]; then
            success "Ubuntu ${OS_VERSION} (Resolute+) : noyau non affecté."
            VULNERABLE=false
            return
        fi
    fi

    local kver
    kver=$(uname -r | sed 's/-[^0-9].*//')  
    local k_major k_minor k_patch
    k_major=$(echo "$kver" | cut -d. -f1)
    k_minor=$(echo "$kver" | cut -d. -f2)
    k_patch=$(echo "$kver" | cut -d. -f3)
    k_patch=${k_patch:-0}

    VULNERABLE=false

    if (( k_major < 4 )) || (( k_major == 4 && k_minor < 14 )); then
        success "Noyau ${KERNEL_VERSION} antérieur à 4.14 : non affecté."
        return
    fi

    if (( k_major == 6 && k_minor == 18 )); then
        if (( k_patch >= 22 )); then
            success "Noyau ${KERNEL_VERSION} ≥ 6.18.22 : patché."
        else
            warn "Noyau ${KERNEL_VERSION} < 6.18.22 : ${RED}VULNÉRABLE${NC}"
            VULNERABLE=true
        fi
        return
    fi

    if (( k_major == 6 && k_minor == 19 )); then
        if (( k_patch >= 12 )); then
            success "Noyau ${KERNEL_VERSION} ≥ 6.19.12 : patché."
        else
            warn "Noyau ${KERNEL_VERSION} < 6.19.12 : ${RED}VULNÉRABLE${NC}"
            VULNERABLE=true
        fi
        return
    fi

    if (( k_major >= 7 )); then
        success "Noyau ${KERNEL_VERSION} ≥ 7.0 : patché."
        return
    fi

    warn "Noyau ${KERNEL_VERSION} dans la plage affectée (4.14–6.17) : ${RED}VULNÉRABLE${NC}"
    VULNERABLE=true
}

module_is_loaded() {
    grep -qE '^algif_aead ' /proc/modules 2>/dev/null
}

module_is_blacklisted() {
    grep -qr 'install algif_aead /bin/false' /etc/modprobe.d/ 2>/dev/null
}

disable_module() {
    banner "Mitigation : désactivation du module algif_aead"

    local conf="/etc/modprobe.d/disable-algif-aead-cve-2026-31431.conf"

    if module_is_blacklisted; then
        success "Module déjà blacklisté dans /etc/modprobe.d/"
    else
        info "Écriture de ${conf} …"
        cat > "$conf" <<'EOF'
# CVE-2026-31431 "Copy Fail" — disable algif_aead
# See: https://cert.europa.eu/publications/security-advisories/2026-005/
install algif_aead /bin/false
EOF
        success "Module blacklisté de façon persistante."
    fi

    if module_is_loaded; then
        info "Tentative de déchargement du module …"
        if rmmod algif_aead 2>/dev/null; then
            success "Module déchargé avec succès. Pas de redémarrage requis."
        else
            warn "Impossible de décharger le module (en cours d'utilisation)."
            warn "Un redémarrage sera nécessaire pour appliquer la mitigation."
            REBOOT_NEEDED=true
        fi
    else
        success "Module algif_aead non chargé — mitigation immédiatement active."
    fi
}

update_kernel() {
    banner "Mise à jour du noyau via ${PKG_MGR}"

    case "$PKG_MGR" in
        apt)
            info "Mise à jour des index apt …"
            apt-get update -qq
            info "Installation des mises à jour de sécurité …"
            DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y linux-image-generic || \
            DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y
            REBOOT_NEEDED=true
            success "Noyau mis à jour via apt."
            ;;
        dnf)
            info "Nettoyage du cache dnf …"
            dnf clean metadata -q
            info "Mise à jour du noyau …"
            dnf upgrade -y kernel 'kernel-*' || dnf upgrade -y kernel
            REBOOT_NEEDED=true
            success "Noyau mis à jour via dnf."
            ;;
        yum)
            info "Mise à jour du noyau via yum …"
            yum update -y kernel
            REBOOT_NEEDED=true
            success "Noyau mis à jour via yum."
            ;;
        zypper)
            info "Mise à jour du noyau via zypper …"
            zypper --non-interactive refresh
            zypper --non-interactive update -t pattern base kernel-default
            REBOOT_NEEDED=true
            success "Noyau mis à jour via zypper."
            ;;
        pacman)
            info "Mise à jour complète du système via pacman …"
            pacman -Syu --noconfirm linux
            REBOOT_NEEDED=true
            success "Noyau mis à jour via pacman."
            ;;
        *)
            warn "Aucun gestionnaire de paquets reconnu."
            warn "Mise à jour automatique impossible — application de la mitigation de module uniquement."
            PATCH_AVAILABLE=false
            ;;
    esac
}

verify_mitigation() {
    banner "Vérification de la mitigation"

    if module_is_blacklisted; then
        success "Blacklist confirmée dans /etc/modprobe.d/"
    else
        error "Blacklist NON trouvée dans /etc/modprobe.d/ !"
    fi

    if module_is_loaded; then
        warn "Module algif_aead encore chargé → redémarrage requis."
    else
        success "Module algif_aead non actif en mémoire."
    fi
}

print_summary() {
    banner "Résumé"

    echo -e "  CVE        : ${BOLD}CVE-2026-31431 (Copy Fail)${NC}"
    echo -e "  Système    : ${OS_NAME}"
    echo -e "  Noyau      : ${KERNEL_VERSION}"
    echo ""

    if [[ "$VULNERABLE" == "false" ]]; then
        success "Ce système n'est PAS vulnérable. Aucune action requise."
    else
        if [[ "${PATCH_AVAILABLE:-true}" == "true" ]]; then
            success "Mise à jour du noyau effectuée."
        fi
        success "Module algif_aead désactivé (mitigation immédiate)."

        if [[ "${REBOOT_NEEDED:-false}" == "true" ]]; then
            echo ""
            warn "⚠  Un ${BOLD}redémarrage est nécessaire${NC} pour activer le nouveau noyau."
            warn "   Exécutez : ${BOLD}sudo reboot${NC}"
        fi
    fi

    echo ""
    echo -e "  Références :"
    echo -e "    https://copy.fail/"
    echo -e "    https://cert.europa.eu/publications/security-advisories/2026-005/"
    echo ""
}

main() {
    echo ""
    echo -e "${BOLD}${RED}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${RED}║   CVE-2026-31431 — Copy Fail — Fix Script   ║${NC}"
    echo -e "${BOLD}${RED}╚══════════════════════════════════════════════╝${NC}"
    echo ""

    REBOOT_NEEDED=false
    PATCH_AVAILABLE=true

    require_root
    detect_os
    check_vulnerability

    if [[ "$VULNERABLE" == "false" ]]; then
        print_summary
        exit 0
    fi

    disable_module

    update_kernel

    verify_mitigation
    print_summary
}

main "$@"