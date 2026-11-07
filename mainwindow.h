#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSqlDatabase>
#include <QLineEdit>
#include <QTableWidget>
#include <QByteArray>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void addAccount();
    void filterAccounts(const QString &text);
    void revelerMotDePasse();
    void copierMotDePasse();
    void supprimerCompte();

private:
    Ui::MainWindow *ui;
    QSqlDatabase m_db;

    // Widgets de l'UI
    QLineEdit *searchInput;
    QTableWidget *accountsTable;

    // La clé dérivée du mot de passe maître (32 octets)
    QByteArray m_cleMaitre;

    QString obtenirMotDePasseLigne(int row);


    // Fonctions d'initialisation
    void initDatabase();
    void setupUI();
    void loadAccountsFromDB();

    // Gestion du mot de passe maître
    QByteArray demanderMotDePasseMaitre();

    // Fonctions de chiffrement/déchiffrement
    QByteArray chiffrerMotDePasse(const QString &motDePasse, QByteArray &nonceOut);
    QString dechiffrerMotDePasse(const QByteArray &chiffre, const QByteArray &nonce);
    bool verifierMotDePasseMaitre(const QByteArray &cle);

};

#endif // MAINWINDOW_H
