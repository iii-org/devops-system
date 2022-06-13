"""add_excalidraw_related_table

Revision ID: 6edfce07512c
Revises: aeb42c11f16d
Create Date: 2022-06-02 16:48:13.436564

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6edfce07512c'
down_revision = 'aeb42c11f16d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('excalidraw',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=True),
    sa.Column('name', sa.String(), nullable=True),
    sa.Column('room', sa.String(), nullable=False),
    sa.Column('key', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('excalidraw_issue_relation',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('excalidraw_id', sa.Integer(), nullable=True),
    sa.Column('issue_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['excalidraw_id'], ['excalidraw.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('excalidraw_json',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('excalidraw_id', sa.Integer(), nullable=True),
    sa.Column('name', sa.String(), nullable=True),
    sa.Column('json_key', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['excalidraw_id'], ['excalidraw.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('excalidraw_json')
    op.drop_table('excalidraw_issue_relation')
    op.drop_table('excalidraw')
    # ### end Alembic commands ###