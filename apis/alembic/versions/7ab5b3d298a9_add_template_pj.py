"""'add_template_pj'

Revision ID: 7ab5b3d298a9
Revises: b7d3a4a8f308
Create Date: 2022-05-11 12:04:14.758691

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7ab5b3d298a9'
down_revision = 'b7d3a4a8f308'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('template_project',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('template_repository_id', sa.Integer(), nullable=False),
    sa.Column('from_project_id', sa.Integer(), nullable=False),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('template_project')
    # ### end Alembic commands ###
