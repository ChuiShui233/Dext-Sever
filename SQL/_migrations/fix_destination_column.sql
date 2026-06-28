-- 修复 destination_question_id 字段以支持负值（-1表示结束问卷）
-- 确保字段允许 NULL 和负值

USE opensever_250034;

-- 修改字段定义，移除默认值约束，允许 NULL 和负值
ALTER TABLE question_options 
MODIFY COLUMN destination_question_id INT NULL DEFAULT NULL
COMMENT '跳转目标问题ID，-1表示结束问卷，NULL表示默认下一题';

-- 验证修改
DESCRIBE question_options;
