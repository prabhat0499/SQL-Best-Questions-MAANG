CREATE TABLE employee_salaries (
  employee_id INT,
  year INT,
  salary INT
);

INSERT INTO employee_salaries (employee_id, year, salary) VALUES
(1, 2011, 1000),
(1, 2012, 1200),
(1, 2014, 1500),
(2, 2020, 2000),
(2, 2021, 2200),
(2, 2022, 2400);

SELECT * FROM employee_salaries
-- find the employees with salary hike in 3 consecutive years
-- two employees 1 and 2
-- salary should increase in 3 consecutive years (year 1 : 100, year 2: 120, year 3 : 150)

WITH con AS (
	SELECT 
		employee_id, salary, year,
		LAG (year) OVER (PARTITION BY employee_id) AS lag_year,  
		LEAD(year) OVER (PARTITION BY employee_id) AS lead_year,
		year-1 AS prev_year,
		year+1 AS next_year,
        LAG(salary) OVER (PARTITION BY employee_id) AS lag_salary,
        LEAD(salary) OVER (PARTITION BY employee_id) AS lead_salary
	FROM employee_salaries
)
-- SELECT * FROM con
SELECT *
FROM con
WHERE 
	lag_year=prev_year AND
    lead_year=next_year AND
    salary > lag_salary AND
    salary < lead_salary
    
-- This ensures:
-- The row is in the middle of 3 consecutive years
-- Salaries are strictly increasing over those 3 years