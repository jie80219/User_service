# user_service

Demo user service in microservice architecture

## 指令

### 初始次部署
初次部署環境請記得建立 `anser_project_network` 網路，以利服務間的溝通。

`docker network create anser_project_network`

### 啟動開發環境
`docker compose up` 或 `docker compose up -d`
當你執行 `docker compose up` 後，將自動初始化專案 Vendor 資料夾與打開伺服器。

### 關閉開發環境
`docker-compose down`

### 初始化資料庫
`docker-compose exec user-service php spark migrate`

### 執行資料表資料填充
`docker-compose exec user-service php spark db:seed UserSeeder`
將建立 5 筆使用者資料。
帳號：user1@anser.io ~ user5@anser.io
密碼：password

## 可用 API

請參考根目錄下的 `user_service.postman_collection.json` 檔案，將可使用的 API 匯入 Postman 中。