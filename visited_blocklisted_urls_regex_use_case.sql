DROP TABLE IF EXISTS Users
DROP TABLE IF EXISTS Blocklist
DROP TABLE IF EXISTS Visited_Urls

CREATE TABLE Users (
  name VARCHAR(50),
  age INT
);

INSERT INTO Users (name, age) VALUES
('Maria', 25),
('Teo', 10),
('Kate', 18),
('Mark', 6);

CREATE TABLE Blocklist (
  url VARCHAR(255),
  threat VARCHAR(50)
);

INSERT INTO Blocklist (url, threat) VALUES
('abc123.xyz/', 'PHISHING'),
('88.23.19.53/down/a.exe', 'MALWARE'),
('1234.co/amazon/', 'SE'),
('some-malware.site/install.exe', 'MALWARE'),
('phishing.fake/login', 'PHISHING');


CREATE TABLE Visited_Urls (
  name VARCHAR(50),
  url VARCHAR(255)
);

INSERT INTO Visited_Urls (name, url) VALUES
('Kate', 'abc123.xyz/'),                          -- ✅ match
('Teo', '1234.co/amazon/'),                       -- ✅ match
('Maria', '88.23.19.53/down/a.exe'),              -- ✅ match
('Mark', 'example.com/home'),                     -- ❌ no match
('Kate', 'safe-site.org/landing'),                -- ❌ no match
('Teo', 'someotherdomain.com/malware.php');       -- ❌ no match


SELECT * FROM Users
SELECT * FROM Blocklist
SELECT * FROM Visited_Urls

-- 1. Find users who visited URLs that are exactly listed in the blocklist.

-- Find those users who have visited the blocklisted urls

SELECT vu.name, b.Url AS blocklisted_urls
FROM Visited_Urls AS vu
JOIN Blocklist b
ON vu.Url=b.Url

-- 2. Find users who visited URLs where the blocklist URL is a prefix of the visited URL.

-- Users whose visted_urls are starting with prefix of blocklisted urls
SELECT vu.name, b.Url AS blocklisted_urls
FROM Visited_Urls AS vu
JOIN Blocklist b
ON vu.Url LIKE CONCAT(b.Url,'%')   -- Join visited_url with prefix of blocklisted url

-- Pointers--
-- LIKE 'abc%'  → matches: 'abc', 'abc123', 'abclogin.php' (use it with 'WHEN')
-- LIKE '%abc'  → matches: '123abc', 'myabc', 'home/abc'
-- Blocklist table's prefix - 'b.Url%' for the entire column
-- CONCAT (b.url, '%') - (say) 'abc123.xyz/%' - 'string%' - signifies prefix
-- Join visited_url with prefix of blocklisted url
-- USE CONCAT(string_column, '%') - Only when Joining Tables and matching prefix/suffix patterns
-- CONCAT (b.url,'%') - starts with b.url
-- CONCAT ('%',b.url) - ends with b.url
-- CONCAT ('%',b.url,'%') - Contains b.url anywhere

-- 3. List all visited URLs that are not in the blocklist at all (neither exact nor prefix).

-- You can join these two tables using two methods
-- Method 1 - normal vu.url = b.url
-- Method 2 - vu.url LIKE CONCAT(b.url,'%') - prefix matching

-- If join by method 1, it will join but 
-- since its string (spaces, commas) will not be exact with other url column in another table
-- So, prefix matching is good or may %b.url% is also works

SELECT vu.Url AS visited_url, b.Url AS blocklisted_matched
FROM Visited_Urls AS vu                 -- LEFT JOIN - All visitor_urls & matched blocklisted_urls
LEFT JOIN Blocklist b
ON vu.Url LIKE CONCAT('%',b.Url,'%')    -- blocklisted_url coming anywhere in the visited_url
WHERE b.Url IS NULL

-- These visited_urls are Clean

-- 4. Find users who visited the same blocked domain more than once.

-- users, vistor_urls matching blocked_urls
-- COUNT 
-- extract the domains of blocked_urls

SELECT vu.name, b.Url AS blocked_domain, COUNT(*) AS visit_count
FROM Visited_Urls AS vu                 
JOIN Blocklist b
  ON vu.Url LIKE CONCAT(b.Url, '%')
GROUP BY vu.name, b.Url
HAVING COUNT(*) > 1;

-- 5. Get a list of all users who visited any URL that matches a blocked domain, with the associated threat type.

SELECT vu.name, b.Url AS blocklisted_urls, threat
FROM Visited_Urls AS vu
JOIN Blocklist b
ON vu.Url LIKE CONCAT(b.Url,'%')

-- -----------------------------------------------------------------------------------------------

-- REGEX /PATTERN MATCHING ! 
-- Regex functions allow you to match or extract patterns from strings using regular expressions
-- Function for Matching - REGEXP or RLIKE | Function for Extracting - REGEXP_SUBSTR()

-- SELECT * FROM urls WHERE url REGEXP '.' - matches any single character,
-- string column having atleast single character, it's not empty - useful to detect empty strings


-- SELECT * FROM users WHERE name REGEXP '[0-9]'; - matches any name containing a number from 0-9
-- SELECT * FROM users WHERE name REGEXP '\\badmin\\b'; - matches exact word - "admin" (say)
-- \\b is word boundary - '\\b string \\b'

-- SELECT * FROM urls WHERE url REGEXP '^https'; - starts with a word
-- Matches URLs that start with https
-- '^ string_start_with'

-- SELECT * FROM urls WHERE url REGEXP '\\.php$'; - ends with a word
-- Matches URLs that ends with .php
-- 'string_ending_with$'
-- '\\.php$' , where \\. to skip the dot

-- SQL Injection Pattern 
-- SELECT * FROM urls WHERE url REGEXP '1=1|or\\s+1=1|union\\s+select';

-- Match Email Format
-- SELECT * FROM contacts WHERE email REGEXP '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$';

-- Extract domain from email
-- SELECT REGEXP_EXTRACT(email, r'@(.+)$') AS domain FROM contacts;

-- Find if string contains special characters
-- SELECT * FROM messages WHERE body REGEXP '[^A-Za-z0-9 ]';


-- \. Literal dot - backwardf slash (\) chnages the meaning in regex
-- Forward slash is just normal expression

-- -------------------------------------------------------------------
-- 1. Find visited URLs that match patterns typically used in SQL injection (e.g., URLs with ' AND 1=1).

-- 1=1 is a tautology — a logical expression that is always true.
-- Detection using WHEERE LIKE '%1=1%'

-- 2. Detect visited URLs containing IP addresses using regex

-- Format of a IP Address - X.X.X.X  - IP = | 4 numbers separated by dots is an IP Address
-- X is a number from 0 to 255
-- 192.168.0.1 | 88.23.19.53 | 10.0.0.255
-- [0-9]{1,3} - matches digit froms 0-9 till 3 digits like (1,23,124,999) and not 1345
-- /. - literal dot | now repeat 3 times and then ADD all the parts

SELECT *
FROM Visited_Urls
WHERE url REGEXP '[0-9]{1,3}(\.[0-9]{1,3}){3}'

-- 3. Identify URLs from the Blocklist table that look like file downloads (e.g., end with .exe, .zip, etc.
SELECT * FROM Blocklist

-- \. literal dot
-- (exe|zip|pdf|...) -- one of the extensions
-- $ end of the string

SELECT *
FROM Blocklist 
WHERE url REGEXP '\.(exe|xyz|pdf...)$'
-- WHERE url REGEXP '\.(exe|xyz|pdf...)/$'  --xyz ends with / and then closing it with $

-- 4. Find users who visited URLs that contain digits followed by ".co/" using regex.

-- digits followed by .co
-- setting the limit of digits - [0-9] , can go till 4 digits {1,4}
-- \. literal dot
-- co' 

SELECT * FROM Visited_Urls
WHERE url REGEXP '[0-9]{1,4}\.co/'

-- 5. Detect users visiting suspicious JavaScript or PHP URLs (e.g., .js, .php, .asp endings).

SELECT * FROM Visited_Urls
WHERE url REGEXP '\.(js|php|exe)$'

