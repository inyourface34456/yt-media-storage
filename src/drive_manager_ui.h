#pragma once

#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QTextEdit>
#include <QFileDialog>
#include <QMessageBox>
#include <QListWidget>
#include <QSplitter>
#include <QGroupBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QComboBox>
#include <QStatusBar>
#include <QTimer>
#include <QThread>

#include <memory>
#include <string>
#include <filesystem>

class WorkerThread : public QThread {
    Q_OBJECT

public:
    enum Operation {
        Encode,
        Decode
    };

    WorkerThread(Operation op, const QString& input, const QString& output,
                 bool encrypt = false, const QString& password = QString(), QObject* parent = nullptr);

signals:
    void progressUpdated(int percentage);
    void statusUpdated(const QString& status);
    void operationCompleted(bool success, const QString& message);
    void logMessage(const QString& message);

protected:
    void run() override;

private:
    Operation operation;
    QString inputPath;
    QString outputPath;
    bool encrypt;
    QString password;
};

class DriveManagerUI : public QMainWindow {
    Q_OBJECT

public:
    DriveManagerUI(QWidget* parent = nullptr);
    ~DriveManagerUI();

private slots:
    void selectInputFile();
    void selectOutputFile();
    void selectInputDirectory();
    void selectOutputDirectory();
    void startEncode();
    void startDecode();
    void startBatchEncode();
    void clearLogs();
    void onOperationCompleted(bool success, const QString& message);
    void onProgressUpdated(int percentage);
    void onStatusUpdated(const QString& status);
    void onLogMessage(const QString& message);
    void updateFileList();
    void removeSelectedFiles();
    void clearFileList();
    void togglePasswordVisibility();

private:
    void setupUI();
    void setupMenuBar();
    void setupStatusBar();
    void connectSignals();
    void resetProgress();
    void logMessage(const QString& message);
    void loadSettings();
    void saveSettings();
    bool validatePaths();

    // UI Components
    QWidget* centralWidget;
    QSplitter* mainSplitter;
    
    // Left panel - File operations
    QGroupBox* fileOperationsGroup;
    QLineEdit* inputFileEdit;
    QLineEdit* outputFileEdit;
    QPushButton* selectInputButton;
    QPushButton* selectOutputButton;
    QCheckBox* encryptCheckBox;
    QLineEdit* passwordEdit;
    QPushButton* passwordVisibilityButton;
    QPushButton* encodeButton;
    QPushButton* decodeButton;
    
    // Batch operations
    QGroupBox* batchGroup;
    QListWidget* fileListWidget;
    QPushButton* addFilesButton;
    QPushButton* removeFilesButton;
    QPushButton* clearFilesButton;
    QPushButton* batchEncodeButton;
    QLineEdit* batchOutputDirEdit;
    QPushButton* batchOutputButton;
    
    // Right panel - Status and logs
    QGroupBox* statusGroup;
    QProgressBar* progressBar;
    QLabel* statusLabel;
    QLabel* progressLabel;
    
    QGroupBox* logsGroup;
    QTextEdit* logTextEdit;
    QPushButton* clearLogsButton;
    
    // Menu and status bar
    QLabel* permanentStatus;
    
    // Settings
    QComboBox* qualityCombo;
    QComboBox* codecCombo;
    
    // Worker thread
    std::unique_ptr<WorkerThread> workerThread;
    
    // State
    bool isOperationRunning;
    QString currentOperation;
};
