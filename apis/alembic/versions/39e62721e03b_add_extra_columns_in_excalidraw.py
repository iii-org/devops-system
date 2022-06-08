"""add_extra_columns_in_excalidraw

Revision ID: 39e62721e03b
Revises: 6edfce07512c
Create Date: 2022-06-06 10:54:13.568752

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '39e62721e03b'
down_revision = '6edfce07512c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('excalidraw', sa.Column('created_at', sa.DateTime(), nullable=True))
    op.add_column('excalidraw', sa.Column('operator_id', sa.Integer(), nullable=True))
    op.add_column('excalidraw', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.create_foreign_key("excalidraw_operator_id_fkey", 'excalidraw', 'user', ['operator_id'], ['id'], ondelete='SET NULL')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint("excalidraw_operator_id_fkey", 'excalidraw', type_='foreignkey')
    op.drop_column('excalidraw', 'updated_at')
    op.drop_column('excalidraw', 'operator_id')
    op.drop_column('excalidraw', 'created_at')
    # ### end Alembic commands ###
