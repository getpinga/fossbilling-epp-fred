# Compatibility

This module is designed for use with FRED Registry (https://fred.nic.cz/en/).

# FOSSBilling Module Installation instructions

## 1. Download and Install FOSSBilling:

Start by downloading the latest version of FOSSBilling from the official website (https://fossbilling.org/). Follow the provided instructions to install it.

## 2. Installation and Configuration of Registrar Adapter:

First, download this repository which contains the fred.php file. After successfully downloading the repository, move the fred.php file into the `[FOSSBilling]/library/Registrar/Adapter` directory.

Next, rename `fred.php` as `YourRegistryName.php`. Please ensure to replace "**YourRegistryName**" with the actual name of your registry.

Proceed to open the newly renamed file and locate the phrase "**Registrar_Adapter_FRED**". Replace it with "**Registrar_Adapter_YourRegistryName**".

## 3. Addition of Synchronization Scripts:

There are two additional scripts in the repository: **fredSync.php** and **fredEpp.php**. These need to be placed in the main `[FOSSBilling]` directory.

Rename `fredSync.php` to `YourRegistryNameSync.php`.

Edit `fredSync.php` and replace **FRED** in the line `$registrar = "FRED";` with the name of your registry provided in step 2.

## 4. Setting Up the Cron Job:

You need to set up a cron job that runs the sync module twice a day. Open crontab using the command `crontab -e` in your terminal.

Add the following cron job:

`0 0,12 * * * php /var/www/html/YourRegistryNameSync.php`

This command schedules the synchronization script to run once every 12 hours (at midnight and noon).

## 5. Activate the Domain Registrar Module:

Within FOSSBilling, go to **System -> Domain Registration -> New Domain Registrar** and activate the new domain registrar.

## 6. Registrar Configuration:

Next, head to the "**Registrars**" tab. Here, you'll need to enter your specific configuration details, including the path to your SSL certificate and key.

## 7. Adding a New TLD:

Finally, add a new Top Level Domain (TLD) using your module from the "**New Top Level Domain**" tab. Make sure to configure all necessary details, such as pricing, within this tab.
