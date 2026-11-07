#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QCheckBox>
#include <QToolButton>
#include <QRandomGenerator>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QHeaderView>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QMessageBox>
#include <QDateTime>
#include <QFrame>
#include <QSqlError>
#include <QSqlQuery>
#include <QDebug>
#include <QInputDialog>
#include <QTimer>
#include <QApplication>
#include <QClipboard>

// INCLUSION DE LIBSODIUM
extern "C" {
#include <sodium.h>
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // 1. Initialisation de la base de données (on a besoin de la DB pour lire/écrire le sel)
    initDatabase();

    // 2. Demander le mot de passe maître
    m_cleMaitre = demanderMotDePasseMaitre();
    if (m_cleMaitre.isEmpty()) {
        QMessageBox::critical(this, "Erreur", "Le mot de passe maître est obligatoire pour ouvrir le coffre.");
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }

    // 3. Mise en place de l'interface
    setupUI();

    // 4. Chargement des données existantes
    loadAccountsFromDB();

    setWindowTitle("G8t - Password Manager");
    resize(1100, 700);
}

MainWindow::~MainWindow()
{
    if (m_db.isOpen()) {
        m_db.close();
    }
    delete ui;
}

// ---------------------------------------------------------
// GESTION DU MOT DE PASSE MAÎTRE ET DU SEL
// ---------------------------------------------------------

QByteArray MainWindow::demanderMotDePasseMaitre()
{
    while (true) { // Boucle pour redemander si le mot de passe est faux
        bool ok;
        QString mdpMaitre = QInputDialog::getText(
            nullptr,
            "G8t - Déverrouillage",
            "Entrez votre mot de passe maître :",
            QLineEdit::Password,
            "",
            &ok
            );

        if (!ok || mdpMaitre.isEmpty()) {
            return QByteArray(); // Annulé par l'utilisateur
        }

        QByteArray sel(crypto_pwhash_SALTBYTES, 0);
        QSqlQuery query(m_db);
        query.exec("SELECT valeur FROM configuration WHERE cle = 'sel'");

        bool premierLancement = !query.next();

        if (premierLancement) {
            // Premier lancement : on génère et on sauvegarde le sel
            randombytes_buf(sel.data(), sel.size());
            QSqlQuery insertQuery(m_db);
            insertQuery.prepare("INSERT INTO configuration (cle, valeur) VALUES ('sel', :sel)");
            insertQuery.bindValue(":sel", sel);
            insertQuery.exec();
        } else {
            sel = query.value(0).toByteArray();
        }

        // Dérivation de la clé
        QByteArray cle(crypto_secretbox_KEYBYTES, 0);
        if (crypto_pwhash(
                reinterpret_cast<unsigned char*>(cle.data()),
                cle.size(),
                mdpMaitre.toUtf8().constData(),
                mdpMaitre.toUtf8().size(),
                reinterpret_cast<const unsigned char*>(sel.constData()),
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_ARGON2ID13) != 0)
        {
            qCritical() << "Erreur lors de la dérivation de la clé.";
            return QByteArray();
        }

        if (premierLancement) {
            // Création du vérificateur pour les prochains lancements
            QByteArray verifClair = "G8t_MASTER_PASSWORD_CHECK";
            QByteArray nonceVerif(crypto_secretbox_NONCEBYTES, 0);
            randombytes_buf(nonceVerif.data(), nonceVerif.size());

            QByteArray verifChiffre(verifClair.size() + crypto_secretbox_MACBYTES, 0);
            crypto_secretbox_easy(
                reinterpret_cast<unsigned char*>(verifChiffre.data()),
                reinterpret_cast<const unsigned char*>(verifClair.constData()),
                verifClair.size(),
                reinterpret_cast<const unsigned char*>(nonceVerif.constData()),
                reinterpret_cast<const unsigned char*>(cle.constData())
                );

            // On stocke le nonce et le chiffré dans la configuration
            QSqlQuery q1(m_db);
            q1.prepare("INSERT INTO configuration (cle, valeur) VALUES ('verif_nonce', :nonce)");
            q1.bindValue(":nonce", nonceVerif);
            q1.exec();

            QSqlQuery q2(m_db);
            q2.prepare("INSERT INTO configuration (cle, valeur) VALUES ('verif_chiffre', :chiffre)");
            q2.bindValue(":chiffre", verifChiffre);
            q2.exec();

            return cle; // Premier lancement OK
        } else {
            // Lancements suivants : on vérifie la clé
            if (verifierMotDePasseMaitre(cle)) {
                return cle; // Mot de passe correct
            } else {
                QMessageBox::warning(nullptr, "Erreur", "Mot de passe maître incorrect. Veuillez réessayer.");
                // La boucle while recommence
            }
        }
    }
}

bool MainWindow::verifierMotDePasseMaitre(const QByteArray &cle)
{
    QSqlQuery query(m_db);

    // Récupérer le nonce
    query.exec("SELECT valeur FROM configuration WHERE cle = 'verif_nonce'");
    if (!query.next()) return false;
    QByteArray nonce = query.value(0).toByteArray();

    // Récupérer le chiffré
    query.exec("SELECT valeur FROM configuration WHERE cle = 'verif_chiffre'");
    if (!query.next()) return false;
    QByteArray verifChiffre = query.value(0).toByteArray();

    QByteArray verifClair(verifChiffre.size() - crypto_secretbox_MACBYTES, 0);

    // Tenter de déchiffrer
    if (crypto_secretbox_open_easy(
            reinterpret_cast<unsigned char*>(verifClair.data()),
            reinterpret_cast<const unsigned char*>(verifChiffre.constData()),
            verifChiffre.size(),
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            reinterpret_cast<const unsigned char*>(cle.constData())
            ) != 0)
    {
        return false; // Échec du déchiffrement = mauvais mot de passe
    }

    return true; // Déchiffrement réussi = bon mot de passe
}

// ---------------------------------------------------------
// BASE DE DONNÉES
// ---------------------------------------------------------

void MainWindow::initDatabase()
{
    m_db = QSqlDatabase::addDatabase("QSQLITE");
    m_db.setDatabaseName("G8t.db");

    if (!m_db.open()) {
        qCritical() << "Impossible d'ouvrir la base de données :" << m_db.lastError().text();
        return;
    }

    QSqlQuery query(m_db);

    // Table pour les comptes
    QString createTableQuery = R"(
        CREATE TABLE IF NOT EXISTS comptes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titre TEXT NOT NULL,
            identifiant TEXT NOT NULL,
            categorie TEXT,
            mot_de_passe_chiffre BLOB NOT NULL,
            nonce BLOB NOT NULL
        )
    )";

    if (!query.exec(createTableQuery)) {
        qCritical() << "Erreur lors de la création de la table comptes :" << query.lastError().text();
    }

    // Table pour la configuration (stockage du sel)
    query.exec("CREATE TABLE IF NOT EXISTS configuration (cle TEXT PRIMARY KEY, valeur BLOB)");
}

void MainWindow::revelerMotDePasse()
{
    QToolButton *button = qobject_cast<QToolButton*>(sender());
    if (!button) return;

    int id = button->property("compte_id").toInt();

    QWidget *passwordWidget = qobject_cast<QWidget*>(button->parent());
    if (!passwordWidget) return;

    QLabel *passwordLabel = passwordWidget->findChild<QLabel*>();
    if (!passwordLabel) return;

    // 1. Si le mot de passe est déjà affiché, on le recache sans redemander
    if (passwordLabel->text() != "••••••••") {
        passwordLabel->setText("••••••••");
        button->setText("👁");
        return;
    }

    // 2. On demande le mot de passe maître pour vérification
    bool ok;
    QString mdpSaisi = QInputDialog::getText(
        this,
        "Confirmation de sécurité",
        "Veuillez confirmer votre mot de passe maître\npour afficher ce mot de passe :",
        QLineEdit::Password,
        "",
        &ok
        );

    if (!ok || mdpSaisi.isEmpty()) {
        return; // L'utilisateur a annulé
    }

    // 3. On récupère le sel depuis la base
    QSqlQuery selQuery(m_db);
    selQuery.exec("SELECT valeur FROM configuration WHERE cle = 'sel'");
    if (!selQuery.next()) {
        QMessageBox::critical(this, "Erreur", "Sel introuvable dans la base.");
        return;
    }
    QByteArray sel = selQuery.value(0).toByteArray();

    // 4. On dérive une clé temporaire avec le mot de passe saisi
    QByteArray cleTemporaire(crypto_secretbox_KEYBYTES, 0);
    if (crypto_pwhash(
            reinterpret_cast<unsigned char*>(cleTemporaire.data()),
            cleTemporaire.size(),
            mdpSaisi.toUtf8().constData(),
            mdpSaisi.toUtf8().size(),
            reinterpret_cast<const unsigned char*>(sel.constData()),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        QMessageBox::critical(this, "Erreur", "Erreur lors de la dérivation de la clé.");
        return;
    }

    // 5. On vérifie que la clé temporaire est la bonne
    if (!verifierMotDePasseMaitre(cleTemporaire)) {
        QMessageBox::warning(this, "Mot de passe incorrect",
                             "Le mot de passe maître saisi est incorrect.");
        return;
    }

    // 6. Le mot de passe est bon : on déchiffre et on affiche
    QSqlQuery query(m_db);
    query.prepare("SELECT mot_de_passe_chiffre, nonce FROM comptes WHERE id = :id");
    query.bindValue(":id", id);

    if (!query.exec() || !query.next()) {
        QMessageBox::warning(this, "Erreur", "Impossible de trouver ce compte dans la base.");
        return;
    }

    QByteArray chiffre = query.value(0).toByteArray();
    QByteArray nonce = query.value(1).toByteArray();

    QString motDePasse = dechiffrerMotDePasse(chiffre, nonce);

    if (motDePasse.isEmpty()) {
        QMessageBox::critical(this, "Erreur", "Impossible de déchiffrer le mot de passe.");
        return;
    }

    passwordLabel->setText(motDePasse);
    button->setText("🔒");

    // Recacher automatiquement après 10 secondes
    QTimer::singleShot(10000, this, [passwordLabel, button]() {
        if (passwordLabel->text() != "••••••••") {
            passwordLabel->setText("••••••••");
            button->setText("👁");
        }
    });
}

void MainWindow::loadAccountsFromDB()
{
    accountsTable->setRowCount(0);

    QSqlQuery query("SELECT id, titre, identifiant, categorie FROM comptes", m_db);

    while (query.next()) {
        int row = accountsTable->rowCount();
        accountsTable->insertRow(row);

        int id = query.value(0).toInt();
        QString titre = query.value(1).toString();
        QString identifiant = query.value(2).toString();
        QString categorie = query.value(3).toString();

        QTableWidgetItem *titreItem = new QTableWidgetItem(titre);
        titreItem->setData(Qt::UserRole, id);
        accountsTable->setItem(row, 0, titreItem);

        accountsTable->setItem(row, 1, new QTableWidgetItem(identifiant));

        // --- Widget pour le mot de passe ---
        QWidget *passwordWidget = new QWidget();
        QHBoxLayout *passwordLayout = new QHBoxLayout(passwordWidget);
        passwordLayout->setContentsMargins(10, 0, 10, 0);
        passwordLayout->setSpacing(5);
        passwordLayout->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

        QLabel *passwordLabel = new QLabel("••••••••");
        passwordLabel->setStyleSheet("color: #E8EAF2; font-size: 10pt;");

        // Bouton Œil
        QToolButton *revealButton = new QToolButton();
        revealButton->setText("👁");
        revealButton->setCursor(Qt::PointingHandCursor);
        revealButton->setProperty("compte_id", id);
        revealButton->setFixedSize(30, 30);
        revealButton->setStyleSheet("QToolButton { background: transparent; border: none; font-size: 12pt; color: #9298AA; }"
                                    "QToolButton:hover { color: #A78BFA; }");

        // Bouton Copier
        QToolButton *copyButton = new QToolButton();
        copyButton->setText("📋");
        copyButton->setCursor(Qt::PointingHandCursor);
        copyButton->setProperty("compte_id", id);
        copyButton->setFixedSize(30, 30);
        copyButton->setStyleSheet("QToolButton { background: transparent; border: none; font-size: 12pt; color: #9298AA; }"
                                  "QToolButton:hover { color: #77D6A1; }");

        // Bouton Supprimer
        QToolButton *deleteButton = new QToolButton();
        deleteButton->setText("🗑️");
        deleteButton->setCursor(Qt::PointingHandCursor);
        deleteButton->setProperty("compte_id", id);
        deleteButton->setFixedSize(30, 30);
        deleteButton->setStyleSheet("QToolButton { background: transparent; border: none; font-size: 12pt; color: #9298AA; }"
                                    "QToolButton:hover { color: #FF6B6B; }");

        passwordLayout->addWidget(passwordLabel);
        passwordLayout->addWidget(revealButton);
        passwordLayout->addWidget(copyButton);
        passwordLayout->addWidget(deleteButton);
        passwordLayout->addStretch();

        accountsTable->setCellWidget(row, 2, passwordWidget);

        connect(revealButton, &QToolButton::clicked, this, &MainWindow::revelerMotDePasse);
        connect(copyButton, &QToolButton::clicked, this, &MainWindow::copierMotDePasse);
        connect(deleteButton, &QToolButton::clicked, this, &MainWindow::supprimerCompte);

        accountsTable->setItem(row, 3, new QTableWidgetItem(categorie));
    }
}

// ---------------------------------------------------------
// CHIFFREMENT / DÉCHIFFREMENT
// ---------------------------------------------------------

QByteArray MainWindow::chiffrerMotDePasse(const QString &motDePasse, QByteArray &nonceOut)
{
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    QByteArray motDePasseUtf8 = motDePasse.toUtf8();
    QByteArray chiffre(motDePasseUtf8.size() + crypto_secretbox_MACBYTES, 0);

    crypto_secretbox_easy(
        reinterpret_cast<unsigned char*>(chiffre.data()),
        reinterpret_cast<const unsigned char*>(motDePasseUtf8.constData()),
        motDePasseUtf8.size(),
        nonce,
        reinterpret_cast<const unsigned char*>(m_cleMaitre.constData())
        );

    nonceOut = QByteArray(reinterpret_cast<char*>(nonce), sizeof nonce);
    return chiffre;
}

QString MainWindow::dechiffrerMotDePasse(const QByteArray &chiffre, const QByteArray &nonce)
{
    QByteArray dechiffre(chiffre.size() - crypto_secretbox_MACBYTES, 0);

    if (crypto_secretbox_open_easy(
            reinterpret_cast<unsigned char*>(dechiffre.data()),
            reinterpret_cast<const unsigned char*>(chiffre.constData()),
            chiffre.size(),
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            reinterpret_cast<const unsigned char*>(m_cleMaitre.constData())
            ) != 0)
    {
        qWarning() << "Échec du déchiffrement : mot de passe maître incorrect ou données corrompues.";
        return QString();
    }

    return QString::fromUtf8(dechiffre);
}

// ---------------------------------------------------------
// INTERFACE GRAPHIQUE
// ---------------------------------------------------------

void MainWindow::setupUI()
{
    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    QHBoxLayout *mainLayout = new QHBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // BARRE LATERALE
    QWidget *sidebar = new QWidget;
    sidebar->setObjectName("sidebar");
    sidebar->setFixedWidth(220);

    QVBoxLayout *sideLayout = new QVBoxLayout(sidebar);
    sideLayout->setContentsMargins(20, 25, 20, 20);
    sideLayout->setSpacing(12);

    QLabel *logo = new QLabel("◆ G8t");
    logo->setObjectName("logo");
    sideLayout->addWidget(logo);

    QLabel *sectionLabel = new QLabel("ESPACE PERSONNEL");
    sectionLabel->setObjectName("sectionLabel");
    sideLayout->addSpacing(25);
    sideLayout->addWidget(sectionLabel);

    QPushButton *allButton = new QPushButton("▦   Tous les comptes");
    QPushButton *favoritesButton = new QPushButton("☆   Favoris");
    QPushButton *secureButton = new QPushButton("♙   Notes sécurisées");

    allButton->setObjectName("navActive");
    favoritesButton->setObjectName("navButton");
    secureButton->setObjectName("navButton");

    sideLayout->addWidget(allButton);
    sideLayout->addWidget(favoritesButton);
    sideLayout->addWidget(secureButton);

    sideLayout->addStretch();

    QLabel *offlineLabel = new QLabel("●  Coffre local");
    offlineLabel->setObjectName("offlineLabel");
    sideLayout->addWidget(offlineLabel);

    // CONTENU PRINCIPAL
    QWidget *content = new QWidget;
    QVBoxLayout *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(35, 30, 35, 30);
    contentLayout->setSpacing(18);

    QLabel *heading = new QLabel("Mes mots de passe");
    heading->setObjectName("heading");

    QLabel *subtitle = new QLabel("Retrouvez et organisez vos identifiants.");
    subtitle->setObjectName("subtitle");

    contentLayout->addWidget(heading);
    contentLayout->addWidget(subtitle);

    // BARRE DE RECHERCHE ET BOUTON
    QHBoxLayout *toolbar = new QHBoxLayout;

    searchInput = new QLineEdit;
    searchInput->setPlaceholderText("Rechercher un compte...");
    searchInput->setMinimumHeight(42);

    QPushButton *addButton = new QPushButton("+ Ajouter un compte");
    addButton->setObjectName("primaryButton");
    addButton->setMinimumHeight(42);

    toolbar->addWidget(searchInput, 1);
    toolbar->addWidget(addButton);

    contentLayout->addLayout(toolbar);

    // TABLEAU
    accountsTable = new QTableWidget(0, 4);
    accountsTable->verticalHeader()->setDefaultSectionSize(50); // Hauteur de 50 pixels
    accountsTable->setHorizontalHeaderLabels({"SERVICE", "IDENTIFIANT", "MOT DE PASSE", "CATÉGORIE"});
    accountsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    accountsTable->verticalHeader()->setVisible(false);
    accountsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    accountsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    accountsTable->setShowGrid(false);
    accountsTable->setAlternatingRowColors(true);

    contentLayout->addWidget(accountsTable);

    // CONNEXIONS
    connect(addButton, &QPushButton::clicked, this, &MainWindow::addAccount);
    connect(searchInput, &QLineEdit::textChanged, this, &MainWindow::filterAccounts);

    connect(allButton, &QPushButton::clicked, this, [this]() {
        searchInput->clear();
    });

    connect(favoritesButton, &QPushButton::clicked, this, []() {
        QMessageBox::information(nullptr, "Favoris", "La fonctionnalité Favoris sera ajoutée plus tard.");
    });

    connect(secureButton, &QPushButton::clicked, this, []() {
        QMessageBox::information(nullptr, "Notes sécurisées", "Les notes sécurisées seront ajoutées plus tard.");
    });

    mainLayout->addWidget(sidebar);
    mainLayout->addWidget(content, 1);

    // STYLE
    setStyleSheet(R"(
        QMainWindow, QWidget { background-color: #11131B; color: #E8EAF2; font-family: "Segoe UI"; font-size: 10pt; }
        QWidget#sidebar { background-color: #191C28; }
        QLabel#logo { color: #A78BFA; font-size: 23pt; font-weight: bold; }
        QLabel#sectionLabel { color: #777D91; font-size: 8pt; font-weight: bold; }
        QLabel#heading { font-size: 25pt; font-weight: bold; }
        QLabel#subtitle { color: #9298AA; }
        QPushButton { background-color: #242838; color: #DDE0EA; border: none; border-radius: 8px; padding: 11px; text-align: left; }
        QPushButton:hover { background-color: #34394D; }
        QPushButton#navActive { background-color: #30264D; color: #C4B5FD; }
        QPushButton#primaryButton { background-color: #7955D9; color: white; font-weight: bold; padding-left: 18px; padding-right: 18px; }
        QPushButton#primaryButton:hover { background-color: #906FEA; }
        QLineEdit { background-color: #1D2130; border: 1px solid #30364A; border-radius: 8px; padding: 10px; color: white; }
        QLineEdit:focus { border: 1px solid #9875ED; }
        QTableWidget { background-color: #191D2A; alternate-background-color: #1E2231; border: 1px solid #292E40; border-radius: 10px; padding: 8px; }
        QHeaderView::section { background-color: #191D2A; color: #858CA2; border: none; padding: 12px; font-size: 8pt; font-weight: bold; }
        QTableWidget::item { padding: 10px; border: none; }
        QTableWidget::item:selected { background-color: #393052; }
        QLabel#offlineLabel { color: #77D6A1; }

        /* --- STYLE POUR LES BOUTONS DANS LE TABLEAU (ŒIL) --- */
        QTableWidget QPushButton {
            background-color: transparent;
            border: none;
            font-size: 14pt;
            text-align: center;
            padding: 0px;
        }
        QTableWidget QPushButton:hover {
            background-color: #34394D;
            border-radius: 4px;
        }
    )");
}

void MainWindow::addAccount()
{
    QDialog dialog(this);
    dialog.setWindowTitle("Ajouter un compte");
    dialog.setMinimumWidth(430);

    QVBoxLayout *layout = new QVBoxLayout(&dialog);
    QFormLayout *form = new QFormLayout;

    QLineEdit *serviceInput = new QLineEdit;
    QLineEdit *usernameInput = new QLineEdit;
    QLineEdit *passwordInput = new QLineEdit;
    QLineEdit *categoryInput = new QLineEdit;

    serviceInput->setPlaceholderText("Ex : Google");
    usernameInput->setPlaceholderText("Ex : monmail@gmail.com");
    passwordInput->setPlaceholderText("Saisir un mot de passe");
    categoryInput->setPlaceholderText("Ex : Personnel");

    passwordInput->setEchoMode(QLineEdit::Password);

    QCheckBox *showPassword = new QCheckBox("Afficher le mot de passe");
    connect(showPassword, &QCheckBox::toggled, this, [passwordInput](bool checked) {
        passwordInput->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
    });

    QPushButton *generateButton = new QPushButton("Générer un mot de passe");
    connect(generateButton, &QPushButton::clicked, this, [passwordInput]() {
        const QString characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
        QString generatedPassword;
        for (int i = 0; i < 20; ++i) {
            int index = QRandomGenerator::system()->bounded(characters.size());
            generatedPassword.append(characters.at(index));
        }
        passwordInput->setText(generatedPassword);
    });

    form->addRow("Service :", serviceInput);
    form->addRow("Identifiant :", usernameInput);
    form->addRow("Mot de passe :", passwordInput);
    form->addRow("", showPassword);
    form->addRow("", generateButton);
    form->addRow("Catégorie :", categoryInput);

    layout->addLayout(form);

    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    layout->addWidget(buttons);

    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    if (dialog.exec() != QDialog::Accepted)
        return;

    if (serviceInput->text().trimmed().isEmpty() || passwordInput->text().isEmpty()) {
        QMessageBox::warning(this, "Champ manquant", "Le service et le mot de passe sont obligatoires.");
        return;
    }

    QByteArray nonce;
    QByteArray chiffre = chiffrerMotDePasse(passwordInput->text(), nonce);

    QSqlQuery query(m_db);
    query.prepare("INSERT INTO comptes (titre, identifiant, categorie, mot_de_passe_chiffre, nonce) "
                  "VALUES (:titre, :identifiant, :categorie, :chiffre, :nonce)");

    query.bindValue(":titre", serviceInput->text().trimmed());
    query.bindValue(":identifiant", usernameInput->text().trimmed());
    query.bindValue(":categorie", categoryInput->text().trimmed());
    query.bindValue(":chiffre", chiffre);
    query.bindValue(":nonce", nonce);

    if (query.exec()) {
        int newId = query.lastInsertId().toInt();

        int row = accountsTable->rowCount();
        accountsTable->insertRow(row);

        // Colonne 0 : Titre (avec l'id caché)
        QTableWidgetItem *titreItem = new QTableWidgetItem(serviceInput->text().trimmed());
        titreItem->setData(Qt::UserRole, newId);
        accountsTable->setItem(row, 0, titreItem);

        // Colonne 1 : Identifiant
        accountsTable->setItem(row, 1, new QTableWidgetItem(usernameInput->text().trimmed()));

        // Colonne 2 : Mot de passe avec bouton œil
        QWidget *passwordWidget = new QWidget();
        QHBoxLayout *passwordLayout = new QHBoxLayout(passwordWidget);
        passwordLayout->setContentsMargins(10, 0, 10, 0);
        passwordLayout->setSpacing(10);
        passwordLayout->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

        QLabel *passwordLabel = new QLabel("••••••••");
        passwordLabel->setStyleSheet("color: #E8EAF2; font-size: 10pt;");

        QToolButton *revealButton = new QToolButton();
        revealButton->setText("👁");
        revealButton->setCursor(Qt::PointingHandCursor);
        revealButton->setProperty("compte_id", newId);
        revealButton->setFixedSize(30, 30);
        revealButton->setStyleSheet("QToolButton { background: transparent; border: none; font-size: 12pt; color: #9298AA; }"
                                    "QToolButton:hover { color: #A78BFA; }");

        passwordLayout->addWidget(passwordLabel);
        passwordLayout->addWidget(revealButton);
        passwordLayout->addStretch();

        accountsTable->setCellWidget(row, 2, passwordWidget);
        connect(revealButton, &QToolButton::clicked, this, &MainWindow::revelerMotDePasse);

        // Colonne 3 : Catégorie
        accountsTable->setItem(row, 3, new QTableWidgetItem(categoryInput->text().trimmed()));
    } else {
        QMessageBox::critical(this, "Erreur", "Impossible d'enregistrer le compte : " + query.lastError().text());
    }
}

void MainWindow::supprimerCompte()
{
    // 1. On récupère le bouton qui a été cliqué
    QToolButton *button = qobject_cast<QToolButton*>(sender());
    if (!button) return;

    // 2. On récupère l'ID du compte
    int id = button->property("compte_id").toInt();

    // 3. On demande une confirmation à l'utilisateur
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(
        this,
        "Confirmer la suppression",
        "Êtes-vous sûr de vouloir supprimer ce compte ?\nCette action est irréversible.",
        QMessageBox::Yes | QMessageBox::No
        );

    // Si l'utilisateur clique sur "Non", on arrête tout
    if (reply != QMessageBox::Yes) {
        return;
    }

    // 4. On supprime de la base de données
    QSqlQuery query(m_db);
    query.prepare("DELETE FROM comptes WHERE id = :id");
    query.bindValue(":id", id);

    if (query.exec()) {
        // 5. On recharge le tableau pour faire disparaître la ligne
        loadAccountsFromDB();
    } else {
        QMessageBox::critical(this, "Erreur", "Impossible de supprimer le compte : " + query.lastError().text());
    }
}

void MainWindow::copierMotDePasse()
{
    // 1. On récupère le bouton qui a été cliqué
    QToolButton *button = qobject_cast<QToolButton*>(sender());
    if (!button) return;

    // 2. On récupère l'ID du compte stocké dans le bouton
    int id = button->property("compte_id").toInt();

    // 3. On va chercher le mot de passe chiffré dans la base
    QSqlQuery query(m_db);
    query.prepare("SELECT mot_de_passe_chiffre, nonce FROM comptes WHERE id = :id");
    query.bindValue(":id", id);

    if (!query.exec() || !query.next()) {
        QMessageBox::warning(this, "Erreur", "Impossible de trouver ce compte dans la base.");
        return;
    }

    QByteArray chiffre = query.value(0).toByteArray();
    QByteArray nonce = query.value(1).toByteArray();

    // 4. On déchiffre le mot de passe avec la clé maître
    QString motDePasse = dechiffrerMotDePasse(chiffre, nonce);

    if (motDePasse.isEmpty()) {
        QMessageBox::critical(this, "Erreur", "Impossible de déchiffrer le mot de passe.");
        return;
    }

    // 5. On copie dans le presse-papiers
    QApplication::clipboard()->setText(motDePasse);

    // 6. On affiche un petit message de confirmation
    QMessageBox::information(this, "Copié !", "Le mot de passe a été copié dans le presse-papiers.");
}

void MainWindow::filterAccounts(const QString &text)
{
    for (int row = 0; row < accountsTable->rowCount(); ++row) {
        bool matches = false;
        for (int column = 0; column < accountsTable->columnCount(); ++column) {
            QTableWidgetItem *item = accountsTable->item(row, column);
            if (item && item->text().contains(text, Qt::CaseInsensitive)) {
                matches = true;
                break;
            }
        }
        accountsTable->setRowHidden(row, !matches);
    }
}
