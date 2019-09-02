package com.dextree.dextreeeth.bean;


public class ETHWallet {
    private Long id;
    private String address;
    private String name;
    private String password;
    private String keystorePath;
    private String mnemonic;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    private String publicKey;
    private boolean isCurrent;
    private boolean isBackup;
    public ETHWallet(Long id, String address, String name, String password,
                     String keystorePath, String mnemonic, boolean isCurrent,
                     boolean isBackup) {
        this.id = id;
        this.address = address;
        this.name = name;
        this.password = password;
        this.keystorePath = keystorePath;
        this.mnemonic = mnemonic;
        this.isCurrent = isCurrent;
        this.isBackup = isBackup;
    }

    public ETHWallet() {
    }

    public boolean isBackup() {
        return isBackup;
    }

    public void setBackup(boolean backup) {
        isBackup = backup;
    }


    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public void setKeystorePath(String keystorePath) {
        this.keystorePath = keystorePath;
    }

    public String getMnemonic() {
        return mnemonic;
    }

    public void setMnemonic(String mnemonic) {
        this.mnemonic = mnemonic;
    }

    public Long getId() {
        return this.id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public boolean isCurrent() {
        return isCurrent;
    }

    public void setCurrent(boolean current) {
        isCurrent = current;
    }

    public boolean getIsCurrent() {
        return this.isCurrent;
    }

    public void setIsCurrent(boolean isCurrent) {
        this.isCurrent = isCurrent;
    }

    public boolean getIsBackup() {
        return this.isBackup;
    }

    public void setIsBackup(boolean isBackup) {
        this.isBackup = isBackup;
    }

    @Override
    public String toString() {
        return "ETHWallet{" +
                "id=" + id +
                ", address='" + address + '\'' +
                ", name='" + name + '\'' +
                ", password='" + password + '\'' +
                ", keystorePath='" + keystorePath + '\'' +
                ", mnemonic='" + mnemonic + '\'' +
                ", isCurrent=" + isCurrent +
                ", isBackup=" + isBackup +
                '}';
    }

}
